# last-server-standing

[library.m0unt41n.ch/challenges/last-server-standing](https://library.m0unt41n.ch/challenges/last-server-standing) ![](../../resources/misc.svg) ![](../../resources/medium.svg) 

# TL;DR

We get a user login into a restricted Linux image. The flag is in root's homedir

# Analysis

Poking few things about the system:

## No networking

```
(none):/$ ip addr
1: lo: <LOOPBACK> mtu 65536 qdisc noop state DOWN qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: eth0: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN qlen 1000
    link/ether 02:35:91:50:83:52 brd ff:ff:ff:ff:ff:ff

(none):/$ ip rule
0:      from all lookup local
32766:  from all lookup main
32767:  from all lookup default
```

## Modified files

Let's see what files have been modified:

### By date

*   `Aug  4 10:01` is what most files are - presumably base image creation
*   `Sep 20 09:27` is the system boot time

```
(none):/$ ls -lad $(find / 2>&1)  | grep -v 'Aug  4 10:01' | grep -v 'Sep 20 09:27'
ls: find:: No such file or directory
ls: /lost+found:: No such file or directory
ls: Permission: No such file or directory
ls: denied: No such file or directory
ls: find:: No such file or directory
ls: /root:: No such file or directory
ls: Permission: No such file or directory
ls: denied: No such file or directory
drwxr-xr-x   15 root     root          1024 Sep 16 18:08 /etc
-rw-r--r--    1 root     root            12 Aug  4 11:59 /etc/host
-rw-r--r--    1 root     root             0 Sep 16 16:51 /etc/motd
-rw-r--r--    1 root     root          1222 Sep 16 18:08 /etc/passwd
-rw-r--r--    1 root     root          1228 Sep 16 18:08 /etc/passwd-
-rw-r-----    1 root     root           553 Sep 16 18:08 /etc/shadow
-rw-r-----    1 root     root           448 Sep 16 18:08 /etc/shadow-
drwxr-xr-x    3 root     root          1024 Sep 16 18:08 /home
drwxr-sr-x    2 user     1001          1024 Sep 20 10:03 /home/user
-rw-------    1 user     1001          2722 Sep 20 10:08 /home/user/.ash_history
dr-xr-xr-x    3 root     root          1024 Aug  4 11:58 /proc
drwxr-xr-x    3 root     root          1024 Aug  4 11:58 /proc/sys
drwxr-xr-x    2 root     root          1024 Aug  4 11:58 /proc/sys/kernel
-rw-r--r--    1 root     root            12 Aug  4 11:58 /proc/sys/kernel/hostname
drwx------    2 root     root          1024 Sep 16 16:58 /root
drwxr-xr-x    2 root     root          4096 Sep 16 16:54 /usr/bin
```

### By md5sum

Compared the MD5 sums of all (accessible) files with 
[alpine-minirootfs-3.12.0-x86.tar.gz](https://dl-cdn.alpinelinux.org/alpine/v3.12/releases/x86/alpine-minirootfs-3.12.0-x86.tar.gz)
from distribution. Changes found:

*   `/etc/group`
    
    ```
     nogroup:x:65533:
     nobody:x:65534:
    -student:x:1000:
    ```
*    `/etc/motd` - replaced generic longer text with empty file
*   Created `/etc/host` and resulting `/proc/sys/kernel/hostname`, as `workstation`
*   `/etc/passwd` - added:

    ```
    user:x:1001:1001:Linux User,,,:/home/user:/usr/bin/bash
    ```
    and then changed shell:
    ```
    -user:x:1001:1001:Linux User,,,:/home/user:/usr/bin/bash
    +user:x:1001:1001:Linux User,,,:/home/user:/bin/sh
    ```

### By file sizes

```
md5sum $(find . -type f) | grep Permission
find: ./lost+found: Permission denied
find: ./root: Permission denied
md5sum: can't open './etc/crontabs/root': Permission denied
md5sum: can't open './etc/shadow': Permission denied
md5sum: can't open './etc/shadow-': Permission denied
md5sum: can't open './lib/apk/db/lock': Permission denied
```

*   Original

    ```
    $ ls -lad etc/crontabs/root etc/shadow etc/shadow- lib/apk/db/lock
    -rw-------. 1 muflon muflon 283 May 28  2020 etc/crontabs/root
    -rw-r-----. 1 muflon muflon 422 May 29  2020 etc/shadow
    -rw-------. 1 muflon muflon   0 May 29  2020 lib/apk/db/lock
    ```
*   Image:

    ```
    $ ls -lad etc/crontabs/root etc/shadow etc/shadow- lib/apk/db/lock
    -rw-------  1 root   root   283 Aug  4 10:01 etc/crontabs/root
    -rw-r-----  1 root   root   553 Sep 16 18:08 etc/shadow
    -rw-r-----  1 root   root   448 Sep 16 18:08 etc/shadow-
    -rw-------  1 root   root     0 Aug  4 10:01 lib/apk/db/lock
    ```

## Busybox

All Busybox links are mapped into executables
```
$ for F in $(busybox --list-full); do ls -ld $F ; done >/dev/null
```

# Now, wait...

I tried clicking on the remote instance twice, to look through
files produced by some of the previous commands. I noticed that
every time it started a new VM.

Then, I noticed that the terminal is running in the browser...

Then, I noticed this is actually running **fully** in a browser &#128578;
(i.e. emulation with JS)

From here, it was easy. `F12` to see how the system is being loaded
(`/blkXXXXXXXXX.bin`) and then, getting these files, extracting the flag.

## Getting the flag

```bash
REMOTE=https://500da51c-0eef-471a-ae15-c508f36ce2b3.library.m0unt41n.ch:1337
for N in $(seq -f "blk%09g.bin" 0 32);
do
  wget $REMOTE/root-x86/$N
done
cat blk*.bin >image.bin
rm blk*.bin
e2ls -la image.bin:/root
e2tail image.bin:/root/flag.txt
```

Result: `echo U0NEe2MwMGxfdzNiYnIwd3Mzcl9WTV9nMF9icnJycnJycn0K | base64 -d`

---

## `SCD{c00l_w3bbr0ws3r_VM_g0_brrrrrrr}`




<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
