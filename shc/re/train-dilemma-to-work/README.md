# train-dilemma-to-work

[library.m0unt41n.ch/challenges/train-dilemma-to-work](https://library.m0unt41n.ch/challenges/train-dilemma-to-work) ![](../../resources/re.svg) ![](../../resources/hard.svg) 

# TL;DR

We are given a `train` binary (md5sum: `4e7572fcbbbd99cb2fcf34826d87f67c`),
which reads a flag from the standard input and verifies whether it is a right
one. The binary is statically linked, stripped, heavily self-encrypted and uses
anti-debugging measures.

What we do:

*   Disable `TracerPid`-based debugger protection.
*   Analyze the decryption routines and persistently decrypt a bunch of code
    offline (editing the ELF), so that we can work with debugger more easily.
*   Once decrypted, reverse-engineer the code that verifies the flag.
*   Notice that the flag is verified one-bit-at-a-time and bit's "correctness"
    is determined with a `complicated_function`.
*   **Don't** try to reverse-engineer the flag and that `complicated_function`.
    Instead:
    *   Send a flag consisting of zeros.
    *   Inject shellcode after the return from the `complicated_function`,
        which collects return values in a buffer on a side.
    *   Aggregate all these return values into a correct flag and print it.

## General notes

*   Tools used: [IDA Free](https://hex-rays.com/ida-free/),
    [pwntools](https://docs.pwntools.com/en/stable),
    [strace](https://man7.org/linux/man-pages/man1/strace.1.html).
*   This write-up is very heavy on hex addresses. It is best followed along
    with a running IDA and jumping around all these addresses provided - with
    either the original binary, or a decrypted one - which you will get by
    following the steps here.
*   This is intentionally very long and detailed, I wanted the full *train* of
    thought, not just the resulting cryptic script.
*   I could probably use IDA decompiler a bit more to make it shorter (e.g. for
    encryption parts).
*   I have very few experience in solving such challenges, and I might have
    unnecessarily complicated this &#128522;

Let's get cracking! &#128578;

<br>

# Initialize pwntools

```python
#!/usr/bin/python3
import os
import pwn
pwn.context(arch='amd64', os='linux')
elf = pwn.ELF('train')
```

Result:

> ```
> [*] '/home/muflon/work/shc/train-dilemma-to-work/train'
>     Arch:     amd64-64-little
>     RELRO:    No RELRO
>     Stack:    No canary found
>     NX:       NX unknown - GNU_STACK missing
>     PIE:      No PIE (0x400000)
>     Stack:    Executable
>     RWX:      Has RWX segments
> ```

Good, most protections are off. But we have no symbols and the binary is
statically linked. I tried to look for some [IDA FLIRT
signatures](https://www.google.com/search?q=ida+flirt+signatures), but could
not find anything that would resolve non-trivial amount of symbols.

(Note: after all the reverse-engineering, I was able to identify [some libc
symbols](#symbols))

# Bypass debugger protection

First thing I noticed is that, when the code is started under debugger, it
exits prematurely:

> ```
> $ strace -i ./train
> [00007f051aad74eb] execve("./train", ["./train"], 0x7ffe6e243f88 /* 81 vars */) = 0
> [0000000000415138] arch_prctl(ARCH_SET_FS, 0x417c18) = 0
> [0000000000411e3c] set_tid_address(0x417d50) = 215360
> [00007ffd9d7494ec] mprotect(0x401000, 16777215, PROT_READ|PROT_WRITE|PROT_EXEC) = -1 ENOMEM
> [000000000040ddb5] open("/proc/self/status", O_RDONLY|O_LARGEFILE) = 3
> [00000000004128f7] brk(NULL)            = 0x8ac000
> [000000000041291c] brk(0x8ae000)        = 0x8ae000
> [0000000000413d18] mmap(0x8ac000, 4096, PROT_NONE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x8ac000
> [0000000000413d18] mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f60b3e42000
> [0000000000414b92] read(3, "Name:\ttrain\nUmask:\t0022\nState:\tR"..., 1024) = 1024
> [00000000004152e1] lseek(3, -917, SEEK_CUR) = 107
> [0000000000411fee] exit_group(-1)       = ?
> [????????????????] +++ exited with 255 +++
> ```

This looks like the [standard
technique](https://www.google.com/search?q=anti+debug+tracerpid) of detecting
non-zero `TracerPid` in `/proc/self/status`.  However, I could not easily
locate the procedure doing this, nor the `/proc/self/status` string (spoiler
alert: it was `sub_40CCCF` and all of that is decrypted on the fly, we will get
to it later).  But, I needed some way to work with debugger.

Also note the failed `mprotect()`. We will [get to it later](#mprotect) as well.

## Analyzing the /proc/self/status parser

I have loaded the program into IDA and set a breakpoint after that `sys_read()`
at `414B92` (inside `sub_414AC0`). I started the program and looked at the
execution flow from there:

*   `sub_414AC0` continued doing some more things and returned to `414E35`
    inside `sub_414E00`.
    *   `sub_414E00` returned to `40DC92` inside `sub_40DB70`.
        *   `sub_40DB70` returned to `40CF4B`. The code view in IDA turned red
            and the console reported:

            ```
            [autohidden] IDA has detected that RIP points to an address which is not defined as code.
            Would you like to directly create an instruction at RIP ? -> Yes
            ```

**Looks like we have entered some self-decrypted or generated code!** Luckily, IDA
could make some sense out of it on the fly and suggested that the subroutine
started at `40CCCF`. Let's call it `sub_40CCCF` from now on.

*   Stepping further through `sub_40CCCF` I found out that calls to `sub_40DB70`
    at `40CF46` yield subsequent lines of `/proc/self/status` in the `RDI`
    buffer. Good!
*   I counted through these `sub_40DB70` calls **until one yielded
    `"TracerPid: ..."`**.
*   Then, I stepped until `40CDE9` which had... a bit of more interesting
    assembly code. Here is the annotated version:

    ```asm
    .text:000000000040CDE9 loc_40CDE9:
    ; Initialize the [rbp-16Ch] buffer with 11 characters (encrypted string).
    .text:000000000040CDE9         mov     rax, 0D2236FD96A44A1A4h
    .text:000000000040CDF3         mov     [rbp-16Ch], rax
    .text:000000000040CDFA         mov     dword ptr [rbp-164h], 628C0Ch
    ; Initialize the [rbp-190h] buffer with 32 characters (decryption key).
    .text:000000000040CE04         mov     rax, 0BB731DBC0925D3F0h
    .text:000000000040CE0E         mov     rdx, 0CD067DC68562B668h
    .text:000000000040CE18         mov     [rbp-190h], rax
    .text:000000000040CE1F         mov     [rbp-188h], rdx
    .text:000000000040CE26         mov     rax, 310636130E3EC57Fh
    .text:000000000040CE30         mov     rdx, 8B256B209A81222Ah
    .text:000000000040CE3A         mov     [rbp-180h], rax
    .text:000000000040CE41         mov     [rbp-178h], rdx
    ; Not sure what this does. Looks like padding / extra obfuscation.
    .text:000000000040CE48         mov     byte ptr [rbp-170h], 0
    ; [rbp-0Ch] will be the loop counter - and a pointer within both buffers.
    ; The loop goes from 0 to 0Ch (inclusive!)
    .text:000000000040CE4F         mov     dword ptr [rbp-0Ch], 0
    .text:000000000040CE56         jmp     short loc_40CE97
    .text:000000000040CE58 loc_40CE58:
    ; Load the current byte from the encrypted string into CL
    .text:000000000040CE58         mov     eax, [rbp-0Ch]
    .text:000000000040CE5B         cdqe
    .text:000000000040CE5D         movzx   ecx, byte ptr [rbp+rax-16Ch]
    ; Now, "do some things that look complicated" &#128578; If you look carefully, there
    ; is a lot of noise here, with SAR/SHR/ADD/SUB, but, in the end, all it does is
    ; to ; load the current byte from the decryption key into AL.
    ; The only interesting thing is that the position in the key is calculated
    ; modulo 32. Which is irrelevant here, but will be relevant later, when we will
    ; be decrypting longer buffers this way.
    .text:000000000040CE65         mov     edx, [rbp-0Ch]
    .text:000000000040CE68         mov     eax, edx
    .text:000000000040CE6A         sar     eax, 1Fh  ; hint: already now EAX=0 &#128578;
    .text:000000000040CE6D         shr     eax, 1Bh
    .text:000000000040CE70         add     edx, eax
    .text:000000000040CE72         and     edx, 1Fh  ; key position is mod(32)
    .text:000000000040CE75         sub     edx, eax
    .text:000000000040CE77         mov     eax, edx
    .text:000000000040CE79         cdqe
    .text:000000000040CE7B         movzx   eax, byte ptr [rbp+rax-190h]
    ; XOR both bytes.
    .text:000000000040CE83         xor     ecx, eax
    ; Write the decrypted byte back to the (not any more) encrypted string.
    .text:000000000040CE85         mov     edx, ecx
    .text:000000000040CE87         mov     eax, [rbp-0Ch]
    .text:000000000040CE8A         cdqe
    .text:000000000040CE8C         mov     [rbp+rax-16Ch], dl
    ; Proceed to the next character.
    .text:000000000040CE93         add     dword ptr [rbp-0Ch], 1
    .text:000000000040CE97
    .text:000000000040CE97 loc_40CE97:
    ; Note the JLE, not JL. The loop is still executed for 0Ah.
    .text:000000000040CE97         cmp     dword ptr [rbp-0Ch], 0Ah
    .text:000000000040CE9B         jle     short loc_40CE58
    ```

The comments above should be self-explanatory - this is simply XOR-decrypting a
11-byte string using a 32-byte key. The one thing to remember (we will see
this code again) is that the loop exit condition is `JLE`. So, if we see
`cmp dword ptr [rbp-0Ch], 0Ah`, this means the loop iterates `0Bh` times and
`0Ah` is the last value.

I now stepped through the above code and, once the loop was complete, the
`[rbp-16Ch]` buffer contained... no less than `"TracerPid:"` string! What
followed after:
```asm
.text:000000000040CE9D         lea     rcx, [rbp-16Ch]   ; "TracerPid:"
.text:000000000040CEA4         lea     rax, [rbp-160h]   ; "TracerPid: 123456\n"
.text:000000000040CEAB         mov     edx, 0Ah          ; strlen("TracerPid:")
.text:000000000040CEB0         mov     rsi, rcx
.text:000000000040CEB3         mov     rdi, rax
.text:000000000040CEB6         call    sub_410A70
.text:000000000040CEBB         test    eax, eax
.text:000000000040CEBD         jnz     short loc_40CEE5
```

... looked a lot like `strncmp()`  - and even returned `0` in `EAX`. I changed
it to `1` in IDA, continue the program and... it went further! (i.e.  did not
bail out).

> BTW, here is a short snippet which can do that XOR decryption with arbitrary
> arguments.
>
> ```python
> from pwnlib.util.packing import *
> code = p64(0x0D2236FD96A44A1A4) + p16(0x8C0C) + p8(0x62)
> key = p64(0xBB731DBC0925D3F0) + p64(0xCD067DC68562B668) + p64(0x310636130E3EC57F) + p64(0x8B256B209A81222)
> print("".join([chr(code[i]^key[i%32]) for i in range(11)]))
> ```
> Output: `TracerPid:` &#128512; The snippet will be useful later for decrypting more strings.

## Persistently disabling debugger detector

Now, there is a catch: We can't just patch the above `40CEBD` location in the
binary to jump unconditionally, because it is inside an encrypted section. I
could probably figure out how to patch the *enrypted* value there. But, that
would be complex - and I expected that I will have to deal with encryption way
more anyway.

However, **the `sub_410A70` itself is not encrypted**. And it looked
hand-crafted (e.g. did not have stack canary), so I made a sweeping assumption
that it is used only for this specific comparison and can be fully replaced
with just `return 1;` (and padded with NOPs, to make IDA's job easier).

Let's do this

```python
# Simple function to fill given range with NOPs.
def nopify(start, endplus1):
  for i in range(start, endplus1):
    elf.p8(i, 0x90)

elf.write(0x410A74, pwn.asm("""mov rax,1 ; ret"""))
nopify(0x410A7C, 0x410AED)
elf.save("train_debug")
```

**This worked**. `strace ./train_debug` was no longer stopping after reading
`/proc/self/status`. I still think it is a bit ugly and would much prefer to
disable that check at higher level. [Which I was able to do later](#antidebug).

# Understand the overall program flow

Let's reload our new, debuggable binary in IDA.  To avoid manual inputs, I
redirected a dummy flag file to `stdin` in process options.

The ELF entry point is `40102F` (`start`). Let's start tracing from there.

```asm
.text:000000000040102F start   proc near
.text:000000000040102F         xor     rbp, rbp
.text:0000000000401032         mov     rdi, rsp
.text:0000000000401035         lea     rsi, cs:0
.text:000000000040103C         and     rsp, 0FFFFFFFFFFFFFFF0h
.text:0000000000401040         call    sub_401050
.text:0000000000401045         db      2Eh
.text:0000000000401045         nop     word ptr [rax+rax+00000000h]
.text:000000000040104F         nop
```

The first thing I noticed was that calling `sub_401050` triggered `SIGCLD`
exception in IDA. I will [worry about it later](#sigcld), for now I set the
signal status to _"don't pass, ignore"_. With that, `call sub_401050` yields
the full program execution, all the way to `"Flag not correct"`.

From here, I tracked down the procedure call sequence, every time digging into
the branch of the code that kept on executing the whole thing:

*   `401040: call sub_401050` (see above) (executes the whole thing)
    *   `401072: jmp sub_40D240`
        *   `40D261: call sub_40CF90` (no visible result)
        *   `40D274: jmp sub_40D200` (indirect via `RAX`)
            *   `40D21F: call sub_40D1C0` (no visible result)
            *   `40D231: call sub_401010` (executes the whole thing)
                *   `40D22C: call sub_40C661` (indirect, via `R12`) (executes
                    the whole thing)

... and the things got interesting from here. We will look at `sub_40C661` in
more detail.

# sub\_40C661: Meet (more of) the encrypted code

## <a name="mprotect"></a>Part 1: Unlock text segment for writing

### Prolog

(including this mostly so that below code can be easily referred to where and
how big various buffers are)

```asm
.text:000000000040C661 sub_40C661      proc near
.text:000000000040C661
.text:000000000040C661 var_C0  = qword ptr -0C0h
.text:000000000040C661 var_B8  = qword ptr -0B8h
.text:000000000040C661 var_B0  = qword ptr -0B0h
.text:000000000040C661 var_A8  = qword ptr -0A8h
.text:000000000040C661 var_A0  = byte ptr -0A0h
.text:000000000040C661 var_90  = qword ptr -90h
.text:000000000040C661 var_88  = qword ptr -88h
.text:000000000040C661 var_80  = qword ptr -80h
.text:000000000040C661 var_78  = qword ptr -78h
.text:000000000040C661 var_70  = byte ptr -70h
.text:000000000040C661 var_60  = qword ptr -60h
.text:000000000040C661 var_58  = qword ptr -58h
.text:000000000040C661 var_50  = qword ptr -50h
.text:000000000040C661 var_48  = qword ptr -48h
.text:000000000040C661 var_40  = qword ptr -40h
.text:000000000040C661 var_38  = qword ptr -38h
.text:000000000040C661 var_30  = qword ptr -30h
.text:000000000040C661 var_28  = qword ptr -28h
.text:000000000040C661 var_20  = dword ptr -20h
.text:000000000040C661 var_10  = dword ptr -10h
.text:000000000040C661 var_C   = dword ptr -0Ch
.text:000000000040C661 var_8   = dword ptr -8
.text:000000000040C661 var_4   = dword ptr -4
.text:000000000040C661
.text:000000000040C661         push    rbp
.text:000000000040C662         mov     rbp, rsp
.text:000000000040C665         sub     rsp, 0C0h
```

### Decryption

Below code looks *very* similar to what we have seen already: put some data in a
local `var_60` array, XOR-decrypt it using a 32-byte key in `var_90`. Note that
this time the decrypted buffer is longer than 32.

```asm
.text:000000000040C66C         mov     rax, 96B205F21F39754Eh
.text:000000000040C676         mov     rdx, 0AC7FBA44ADD000Ah
.text:000000000040C680         mov     [rbp+var_60], rax
.text:000000000040C684         mov     [rbp+var_58], rdx
.text:000000000040C688         mov     rax, 0D0262327F97A370h
.text:000000000040C692         mov     rdx, 4D65874223387E23h
.text:000000000040C69C         mov     [rbp+var_50], rax
.text:000000000040C6A0         mov     [rbp+var_48], rdx
.text:000000000040C6A4         mov     rax, 0C6F9EAA44D6821A4h
.text:000000000040C6AE         mov     rdx, 0C7F7A41D93514Bh
.text:000000000040C6B8         mov     [rbp+var_40], rax
.text:000000000040C6BC         mov     [rbp+var_38], rdx
.text:000000000040C6C0         mov     rax, 57FC6E327597AB70h
.text:000000000040C6CA         mov     rdx, 14C026E2C5796772h
.text:000000000040C6D4         mov     [rbp+var_30], rax
.text:000000000040C6D8         mov     [rbp+var_28], rdx
.text:000000000040C6DC         mov     [rbp+var_20], 0AB7E45h
.text:000000000040C6E3         mov     rax, 0C6F352A44D68261Eh
.text:000000000040C6ED         mov     rdx, 5E86A8E5189C514Bh
.text:000000000040C6F7         mov     [rbp+var_90], rax
.text:000000000040C6FE         mov     [rbp+var_88], rdx
.text:000000000040C705         mov     rax, 0DBD357329D6F631h
.text:000000000040C70F         mov     rdx, 4D9A78BD9D383E33h
.text:000000000040C719         mov     [rbp+var_80], rax
.text:000000000040C71D         mov     [rbp+var_78], rdx
.text:000000000040C721         mov     [rbp+var_70], 0
.text:000000000040C725         mov     [rbp+var_4], 0
.text:000000000040C72C         jmp     short loc_40C767

.text:000000000040C72E loc_40C72E:
.text:000000000040C72E         mov     eax, [rbp+var_4]
.text:000000000040C731         cdqe
.text:000000000040C733         movzx   ecx, byte ptr [rbp+rax+var_60]
.text:000000000040C738         mov     edx, [rbp+var_4]
.text:000000000040C73B         mov     eax, edx
.text:000000000040C73D         sar     eax, 1Fh
.text:000000000040C740         shr     eax, 1Bh
.text:000000000040C743         add     edx, eax
.text:000000000040C745         and     edx, 1Fh
.text:000000000040C748         sub     edx, eax
.text:000000000040C74A         mov     eax, edx
.text:000000000040C74C         cdqe
.text:000000000040C74E         movzx   eax, byte ptr [rbp+rax+var_90]
.text:000000000040C756         xor     ecx, eax
.text:000000000040C758         mov     edx, ecx
.text:000000000040C75A         mov     eax, [rbp+var_4]
.text:000000000040C75D         cdqe
.text:000000000040C75F         mov     byte ptr [rbp+rax+var_60], dl
.text:000000000040C763         add     [rbp+var_4], 1
.text:000000000040C767 loc_40C767:
.text:000000000040C767         cmp     [rbp+var_4], 42h
.text:000000000040C76B         jle     short loc_40C72E
```

### Call what we just decrypted

Stack is executable, remember? &#128521;

```asm
.text:000000000040C76D         lea     rdx, [rbp+var_60]
.text:000000000040C771         mov     eax, 0
.text:000000000040C776         call    rdx
```

Stepping into that `call rdx` we see:

```asm
[stack]:00007FFF8075D170       push    rax
[stack]:00007FFF8075D171       push    rbx
[stack]:00007FFF8075D172       push    rcx
[stack]:00007FFF8075D173       push    rdx
[stack]:00007FFF8075D174       push    rsi
[stack]:00007FFF8075D175       push    rdi
[stack]:00007FFF8075D176       push    r8
[stack]:00007FFF8075D178       push    r9
[stack]:00007FFF8075D17A       push    r10
[stack]:00007FFF8075D17C       push    r11
[stack]:00007FFF8075D17E       push    r12
[stack]:00007FFF8075D180       push    r13
[stack]:00007FFF8075D182       push    r14
[stack]:00007FFF8075D184       push    r15
[stack]:00007FFF8075D186       mov     edi, offset _init_proc
[stack]:00007FFF8075D18B       mov     esi, 0FFFFFFh
[stack]:00007FFF8075D190       mov     edx, 7
[stack]:00007FFF8075D195       mov     eax, 0Ah
[stack]:00007FFF8075D19A       syscall     ; LINUX - sys_mprotect
[stack]:00007FFF8075D19C       pop     r15
[stack]:00007FFF8075D19E       pop     r14
[stack]:00007FFF8075D1A0       pop     r13
[stack]:00007FFF8075D1A2       pop     r12
[stack]:00007FFF8075D1A4       pop     r11
[stack]:00007FFF8075D1A6       pop     r10
[stack]:00007FFF8075D1A8       pop     r9
[stack]:00007FFF8075D1AA       pop     r8
[stack]:00007FFF8075D1AC       pop     rdi
[stack]:00007FFF8075D1AD       pop     rsi
[stack]:00007FFF8075D1AE       pop     rdx
[stack]:00007FFF8075D1AF       pop     rcx
[stack]:00007FFF8075D1B0       pop     rbx
[stack]:00007FFF8075D1B1       pop     rax
[stack]:00007FFF8075D1B2       retn
```

So, `mprotect(_init_proc, 0xFFFFFF, PROT_READ|PROT_WRITE|PROT_EXEC)`,
essentially.

### Encrypt back

Presumably the idea here (and overall) is not to leave unecrypted pieces of
code/data in memory, to make coredump analysis a bit harder.

```asm
.text:000000000040C778         mov     [rbp+var_8], 0
.text:000000000040C77F         jmp     short loc_40C7BA
.text:000000000040C781 loc_40C781:
.text:000000000040C781         mov     eax, [rbp+var_8]
.text:000000000040C784         cdqe
.text:000000000040C786         movzx   ecx, byte ptr [rbp+rax+var_60]
.text:000000000040C78B         mov     edx, [rbp+var_8]
.text:000000000040C78E         mov     eax, edx
.text:000000000040C790         sar     eax, 1Fh
.text:000000000040C793         shr     eax, 1Bh
.text:000000000040C796         add     edx, eax
.text:000000000040C798         and     edx, 1Fh
.text:000000000040C79B         sub     edx, eax
.text:000000000040C79D         mov     eax, edx
.text:000000000040C79F         cdqe
.text:000000000040C7A1         movzx   eax, byte ptr [rbp+rax+var_90]
.text:000000000040C7A9         xor     ecx, eax
.text:000000000040C7AB         mov     edx, ecx
.text:000000000040C7AD         mov     eax, [rbp+var_8]
.text:000000000040C7B0         cdqe
.text:000000000040C7B2         mov     byte ptr [rbp+rax+var_60], dl
.text:000000000040C7B6         add     [rbp+var_8], 1
.text:000000000040C7BA
.text:000000000040C7BA loc_40C7BA:
.text:000000000040C7BA         cmp     [rbp+var_8], 42h
.text:000000000040C7BE         jle     short loc_40C781
```

### Decryption snippet

Let's again double-check if a Python decryption snippet will get us the same
shellcode with these values. This is similar to previous one, the difference is
that we also disassemble the output:

> ```python
> import pwn
> from pwnlib.util.packing import *
> from pwnlib.asm import disasm
> pwn.context(arch='amd64', os='linux')
> enc_code = (p64(0x96B205F21F39754E) + p64(0x0AC7FBA44ADD000A) +
>             p64(0x0D0262327F97A370) + p64(0x4D65874223387E23) +
>             p64(0xC6F9EAA44D6821A4) + p64(0x00C7F7A41D93514B) +
>             p64(0x57FC6E327597AB70) + p64(0x14C026E2C5796772) +
>             p64(0x0AB7E45))
> key = (p64(0xC6F352A44D68261E) + p64(0x5E86A8E5189C514B) +
>        p64(0x0DBD357329D6F631) + p64(0x4D9A78BD9D383E33))
> print(disasm(bytes([enc_code[i]^key[i%32] for i in range(0x43)])))
> ```

Result: same as above.

## Part 2: decrypt and execute sub\_40BECB

What followed as part of the same function, was a very similar code, but,
this time, decrypting shellcode in the text segment:

### Load keys into local variables

```asm
.text:000000000040C7C0         mov     rax, 9611CA82CA876936h
.text:000000000040C7CA         mov     rdx, 56AF10461907E232h
.text:000000000040C7D4         mov     [rbp+var_C0], rax
.text:000000000040C7DB         mov     [rbp+var_B8], rdx
.text:000000000040C7E2         mov     rax, 0BE4C5F1B7D607FAFh
.text:000000000040C7EC         mov     rdx, 0C8F28DAD0873AAD7h
.text:000000000040C7F6         mov     [rbp+var_B0], rax
.text:000000000040C7FD         mov     [rbp+var_A8], rdx
```

### Decrypt 0x795 bytes at loc\_40BECB

Remember, the length is what you see in `cmp` but plus one.

```asm
.text:000000000040C804         mov     [rbp+var_A0], 0
.text:000000000040C80B         mov     [rbp+var_C], 0
.text:000000000040C812         jmp     short loc_40C85F
.text:000000000040C814 loc_40C814:
.text:000000000040C814         mov     eax, [rbp+var_C]
.text:000000000040C817         cdqe
.text:000000000040C819         lea     rdx, loc_40BECB
.text:000000000040C820         add     rax, rdx
.text:000000000040C823         movzx   eax, byte ptr [rax]
.text:000000000040C826         mov     ecx, eax
.text:000000000040C828         mov     edx, [rbp+var_C]
.text:000000000040C82B         mov     eax, edx
.text:000000000040C82D         sar     eax, 1Fh
.text:000000000040C830         shr     eax, 1Bh
.text:000000000040C833         add     edx, eax
.text:000000000040C835         and     edx, 1Fh
.text:000000000040C838         sub     edx, eax
.text:000000000040C83A         mov     eax, edx
.text:000000000040C83C         cdqe
.text:000000000040C83E         movzx   eax, byte ptr [rbp+rax+var_C0]
.text:000000000040C846         xor     ecx, eax
.text:000000000040C848         mov     eax, [rbp+var_C]
.text:000000000040C84B         cdqe
.text:000000000040C84D         lea     rdx, loc_40BECB
.text:000000000040C854         add     rax, rdx
.text:000000000040C857         mov     edx, ecx
.text:000000000040C859         mov     [rax], dl
.text:000000000040C85B         add     [rbp+var_C], 1
.text:000000000040C85F loc_40C85F:
.text:000000000040C85F         cmp     [rbp+var_C], 794h
.text:000000000040C866         jle     short loc_40C814
```

### Call it

```asm
.text:000000000040C868         mov     eax, 0
.text:000000000040C86D         call    loc_40BECB
```
Lo and behold: stepping over the `loc_40BECB` executes the entire flag process!

### Encrypt it back

Because, securiiitttaaah!

```asm
.text:000000000040C872         mov     [rbp+var_10], 0
.text:000000000040C879         jmp     short loc_40C8C6
.text:000000000040C87B loc_40C87B:                             ; CODE XREF: sub_40C661+26C↓j
.text:000000000040C87B         mov     eax, [rbp+var_10]
.text:000000000040C87E         cdqe
.text:000000000040C880         lea     rdx, loc_40BECB
.text:000000000040C887         add     rax, rdx
.text:000000000040C88A         movzx   eax, byte ptr [rax]
.text:000000000040C88D         mov     ecx, eax
.text:000000000040C88F         mov     edx, [rbp+var_10]
.text:000000000040C892         mov     eax, edx
.text:000000000040C894         sar     eax, 1Fh
.text:000000000040C897         shr     eax, 1Bh
.text:000000000040C89A         add     edx, eax
.text:000000000040C89C         and     edx, 1Fh
.text:000000000040C89F         sub     edx, eax
.text:000000000040C8A1         mov     eax, edx
.text:000000000040C8A3         cdqe
.text:000000000040C8A5         movzx   eax, byte ptr [rbp+rax+var_C0]
.text:000000000040C8AD         xor     ecx, eax
.text:000000000040C8AF         mov     eax, [rbp+var_10]
.text:000000000040C8B2         cdqe
.text:000000000040C8B4         lea     rdx, loc_40BECB
.text:000000000040C8BB         add     rax, rdx
.text:000000000040C8BE         mov     edx, ecx
.text:000000000040C8C0         mov     [rax], dl
.text:000000000040C8C2         add     [rbp+var_10], 1
.text:000000000040C8C6 loc_40C8C6:                             ; CODE XREF: sub_40C661+218↑j
.text:000000000040C8C6         cmp     [rbp+var_10], 794h
.text:000000000040C8CD         jle     short loc_40C87B
```

### And we're done

```asm
.text:000000000040C8CF         mov     eax, 0
.text:000000000040C8D4         leave
.text:000000000040C8D5         retn
```

# Decrypting loc\_40BECB persistently

From the three examples so far - and a sneak peek at `loc_40BECB` that we just
decrypted (and will analyse as next), it is clear that the above decrypt +
execute + encrypt pattern will be repeated many times, with more functions,
possibly in a nested way. We need to make it more workable with the debugger.

The decryption code above looks self-standing. **Can we turn `loc_40BECB` into
non-encrypted code directly in the ELF binary?** We have the keys, we (think
we) know the algorithm. We would need to:

*   Replace encryption and decryption code with `NOP`s. We already have the
    `nopify()` function for that.
*   Decrypt those `795h` bytes at `loc_40BECB` using above keys and the code
    that we know all too well by now.

Let's create a function for doing the latter as part of the exploit:
```python
# Decrypt an area in the code, using given set of four 64-bit keys.
def decode(start, length, key):
  for i in range(length):
    elf.p8(start+i, elf.u8(start+i)^((key[(i>>3)&0x03]>>((i&0x07)<<3))&0xFF))
```

... and use it right away. Do not frown on all these hex numbers (keys,
addresses) - they are all pasted directly from the above disassembly!

```python
nopify(0x40C7C0,0x40C868)
decode(0x40BECB,1941,[0x9611CA82CA876936,0x56AF10461907E232,0xBE4C5F1B7D607FAF,0xC8F28DAD0873AAD7])
nopify(0x40C892,0x40C8D4)
elf.save("train_debug")
```

Does it work? **Yes!** Or, at very least, does not crash &#128521;

> ```
> $ chmod a+x train_debug
> $ ./train_debug
> << Train >>
> > Flip the switches!
> [+] Flag: shc2024{blah}
> [...] Checking Flag 0.00%
> [...] Checking Flag 0.29%
> [-] Flag not correct.
> ```

Also reloading code in IDA now shows `sub_40BECB` instead of `loc_40BECB`.
Good &#128512;

# Decrypt ALL the codes!

As a next step, we have to repeat the above process, hoping to persistently
decrypt all the code, so that further analysis can be easier. With a mix of
stepping through the program and casually looking at the assembly listing in
IDA, I found following places

*   `sub_40C661` decrypts `sub_40BECB` (1941 bytes)

    ```python
    decode(0x40BECB,1941,[0x9611CA82CA876936,0x56AF10461907E232,0xBE4C5F1B7D607FAF,0xC8F28DAD0873AAD7])
    nopify(0x40C7C0,0x40C868)
    nopify(0x40C892,0x40C8D4)
    ```
    **NOTE**: At this point we need to re-analyze code in IDA, to pick the flow
    from just-decrypted `sub_40C661`.  I ended up doing that refresh after each
    subsequent decrypted routine below, if only to confirm that my boundaries for
    extra NOPs were correct
    *   `sub_40BECB` decrypts/calls/encrypts `sub_40CCCF` (669 bytes), twice

        ```python
        decode(0x40CCCF,669,[0xE4E0C840E45018D6,0xC26835F135A43917,0xF70CF805EF4D4C1A,0x44FC8C8E48523841])
        nopify(0x40BEDD,0x40BF73)
        nopify(0x40BF7D,0x40BFD7)
        nopify(0x40C48A,0x40C4E9)
        nopify(0x40C4EE,0x40C548)
        ```
    *   `sub_40BECB` decrypts/calls `sub_40C925` (937 bytes)

        ```python
        decode(0x40C925,937,[0xF84DF81EDF4BAC2A,0x9812AF0F26AC6587,0xBA7165DB8E9F1578,0x4E7B55C2B7E4E2C3])
        nopify(0x40BFD7,0x40C076)
        ```
        *   `sub_40C925` decrypts/calls/encrypts `sub_40C8D6` (40 bytes)

            ```python
            decode(0x40C8D6,40,[0xFED54656EF81D92F,0x768CD52E82F6E61B,0xC099F7C58956F861,0x678571C1C98EF7CB])
            nopify(0x40CA62,0x40CB07)
            nopify(0x40CB13,0x40CB6D)
            ```
        *   `sub_40C925` decrypts/calls/encrypts `sub_40C8FF` (37 bytes)

            ```python
            decode(0x40C8FF,37,[0x126D01E982E6C01,0xEF83A049716A980B,0x74DE05C018549D54,0x856BA5BA83CA7184])
            nopify(0x40CBB5,0x40CC57)
            nopify(0x40CC61,0x40CCBB)
            ```
    *   `sub_40BECB` decrypts/calls `sub_401139` (40 bytes), twice

        ```python
        decode(0x401139,40,[0xC08503C38F86CFDF,0xB3DA8E0B0B088682,0xE1863958E689FC6D,0x739F2DFA39ACC3F3])
        nopify(0x40C151,0x40C1F6)
        nopify(0x40C205,0x40C25F)
        nopify(0x40C379,0x40C3D3)
        nopify(0x40C3E2,0x40C43C)
        ```
    *   `sub_40BECB` decrypts/calls `sub_40BB7C` (846 bytes)

        ```python
        decode(0x40BB7C,846,[0x52BFED41B50892C5,0xC8B3B529FDD13057,0x46B64558D4CE8336,0x55FA11C3B3980043])
        nopify(0x40C548,0x40C5F0)
        nopify(0x40C5FA,0x40C657)
        ```
        *   `sub_40BB7C` decrypts/calls/encrypts `sub_40CCCF` (669 bytes). It
            is already decrypted! (above)

            ```python
            nopify(0x40BCA1,0x40BD49)
            nopify(0x40BD53,0x40BDB0)
            ```
        *   `sub_40BB7C` decrypts/calls/encrypts `sub_4012DB` (43168 bytes)

            ```python
            decode(0x4012DB,43168,[0xF989557D9488AC9B,0xC2076EEBF34552C1,0x5493D088FC52101D,0x347B90473EC69E9E])
            nopify(0x40BDB0,0x40BE58)
            nopify(0x40BE64,0x40BEC1)
            ```
            *   `sub_4012DB` decrypts/calls/encrypts `sub_40CCCF` (669 bytes),
                twice. It is already decrypted! (above)

                ```python
                nopify(0x4012F4,0x401393)
                nopify(0x40139D,0x4013FA)
                nopify(0x40B808,0x40B865)
                nopify(0x40B8A0,0x40B8FD)
                ```
            *   `sub_4012DB` decrypts/calls/encrypts `sub_401162` (376 bytes).
            
                ```python
                decode(0x401162,376,[0xF35E59A421044432,0xAF609CF5C7C65071,0x55E109DF495F6009,0xE8FE5FE09EE8662F])
                nopify(0x40B70B,0x40B768)
                nopify(0x40B7A6,0x40B803)
                ```

## Ultimate test if we decrypted everyting

To verify that there is no more self-decrypting code in the binary, we can
**disable the `sys_mprotect()` section** found earlier. With that, any further
attempt of code modification should segfault:

```python
nopify(0x40C66C, 0x40C7C0)
elf.save("train_debug")
```

... and resulting ELF still seems to work fine. Additionally, reloading IDA
has decoded the flow of all these additional functions and it now shows them properly,
as `sub_XXXXXX`. Good &#128512;

## Should we decrypt all the data too?

So far, we persistently decrypted the code. However, as we already saw with
`"/proc/self/status"`, there are almost certainly many more places where
similar process is applied to data (e.g. strings that we see when running the
challenge). Should we decrypt them too?

We could, but it would be more complicated: these encrypted data are not stored
as contiguous blocks (like code), but rather spread through many, separate `MOV`
instructions, each of which we would have to individually localize and patch.

There is not *that* much benefit anyway. Sure, there will be some points (some
of them in below write-up) where we e.g. want to understand what strings is
decrypted and printed. But, we can use all the above Python snippets for that
and just annotate respective pieces of code.

Conclusion: **not decrypting data**.

# Let's examine these functions a bit closer

Now that we have fully debuggable code, we can get back to where we paused in
the above analysis of program flow. Which was the `call sub_40becb` at
`40C8B4`.

## sub\_40BECB

This looks like a top-level routine for the entire program flow. It does
everything from the `"<< Train >>"` header, through flag input, all the way up
to the conclusion (flag correct/incorrect). Stepping through the assembly code
and looking at the outputs of the functions called, the flow seems roughly:

*   `40BF73`: `call(sub_40CCCF, eax=0)`
*   `40C076`: `call(sub_411220, rdi=var_98, esi=0, rdx=40C925, ecx=0)`
*   `40C096`: decrypt the `"<< Train >>"` string into `var_A5`
*   `40C1F6`: `call(sub_401139, rdi=var_A5)` - prints it
*   `40C25F`: encrypt `var_A5` back
*   `40C2AD`: decrypt the `"> Flip the switches!"` string into `var_120`
*   `40C3D3`: `call(sub_401139, rdi=var_120)` - prints it
*   `40C43C`: encrypt `var_120` back
*   `40C4E9`: `call(sub_40CCCF)`
*   `40C5F0`: `call(sub_40BB7C, eax=0)` - the rest happens here, starting with
    reading the flag from standard input
*   `40C660`: `ret`

Note that, from now on, debugging has became a bit more annoying, as we have to
step through all these NOPs that we planted instead of code
decryption/encryption routines.

## sub\_40BB7C

Let's now look into that final `sub_40BB7C`, in a similar fashion:

*   `40BB8E`: decrypt the `"[+] Flag: "` string into `var_5C`
*   `40BC30`: `call(sub_40DE80, rdi=var_5C, eax=0)`  - prints it
*   `40BC35`: encrypt `var_5C` back
*   `40BC7A`: `call(sub_40DA00, rdi=417020)`
*   `40BC89`: `call(sub_40DB70, rdi=var_50, rsi=44, rdx=417020)` - reads the flag
    into `var_50`
*   `40BD49`: `call(sub_40CCCF, eax=0)`
*   `40BE58`: `call(sub_4012DB, rdi=var_50)` - the rest happens here, i.e. flag
    verification and verdict
*   `40BECA`: `ret`

## sub\_4012DB

This is the most interesting/important function we will look into - but also it
is much harder to follow in assembly. We will use the IDA-disassembled
version, heavily annotated and made more readable (but without semantic
changes).

If this looks intimidating, don't freak out just yet. Below the code you will
find a description of the thought process which led to these annotations - and
simplified version of the code too.

Note that the encrypted strings were decoded with our previous Python snippets.

```c
__int64 __fastcall sub_4012DB(__int64 a1, char *a2) {
    /*** IDA is wrong, a1 is actually the char* flag, see previous notes. ***/

    /*** Some casual variables. ***/
    unsigned int v2;
    int v3, v4, v5, v6, v8, v10, v11;
    double v7;
    __int64 result;

    /*** This is actually more like __int64 v12[4]. It is used to store the key
         for various decryptions below. ***/
    __int64 v12, v13, v14, v15;
    /*** Unimportant, one byte set to zero after the key for some reason. ***/
    char v16;

    /*** Used to store & decrypt the "[+] Flag not correct." string. ***/
    __int64 v17[4];

    /*** Used to store & decrypt the "[+] Flag Correct!" string. ***/
    __int64 v18[2]; int v19;

    /*** Used to store & decrypt the "[...] Checking Flag %.2f%%\n" string. ***/
    __int64 v20; _QWORD v21[7];
    /*** Unimportant, another zero terminator byte. ***/
    char v22;

    /*** A 344-element int array which is used to define order in which the
         bits in the flag will be checked. Note the size: (43 bytes x 8 bits)
         because all flag operations are capped to 43 bytes indeed. ***/
    int v23[344];

    /*** Below sequence is actually used as a single, large-array-of-int64s ***/
    __int64 *v24;    // [rbp-3F30h]
    __int64 *v25;    // [rbp-3F28h]
    __int64 v26[2];  // [rbp-3F20h]
    __int64 v27[2];  // [rbp-3F10h]
    (...)
    __int64 v961[2]; // [rbp-D0h]
    __int64 v962[2]; // [rbp-C0h]

    /*** Two arrays used during flag checking, but no idea how. ***/
    char v963[16];
    char v964[64];

    /*** Important variable: current index from the bit permutation table. ***/
    int v972;        // [rbp-44h]

    /*** More casual variables. ***/
    int v965, v966, v967, v968, v969, v971, mm, kk, jj, ii, n, m, k, j, i, v982;
    char v970;



    /*** Another debugger check ***/
    sub_40CCCF();

    /*** Initialize the large-array-of-int64s. I am not sure what is actually
         going on here. It looks a bit like programming some sort of a finite
         state automaton. It will not be needed for the solution though. ***/
    v962[0] = (__int64)v964;
    v962[1] = (__int64)v963;
    (...)
    v26[0] = (__int64)v412;
    v26[1] = (__int64)v171;
    v24 = v913;
    v25 = v309;

    /*** flag_correct=1 (see below) ***/
    v982 = 1;

    /*** Initialize v23 with a simple sequence of numbers (thus, initial
         permutation = identity). ***/
    for ( i = 0; i <= 343; ++i )
        v23[i] = i;

    /*** With a brief peek inside both functions, this overall looks like
         srand(time(0)). ***/
    v2 = sub_411AF0(0LL);
    sub_40D2D0(v2);

    /*** Randomly shuffle the permutation table. ***/
    for ( j = 0; j <= 99998; ++j ) {
        /*** sub_40D2E0 looks like rand() ***/
        v968 = (int)sub_40D2E0() % 344;
        v6 = sub_40D2E0();
        v3 = v6 >> 31;
        v967 = v6 % 344;
        /*** Swap two elements of permutation table ***/
        v966 = v23[v968];
        v965 = v23[v6 % 344];
        v23[v968] = v965;
        v23[v967] = v966;
    }

    /*** Not sure what these are, seem not to be used in v20 format string
         (len==28) ***/
    v21[3] = 0xF35E59A421044432LL;
    v21[4] = 0xAF609CF5C7C65071LL;
    v21[5] = 0x55E109DF495F6009LL;
    v21[6] = 0xE8FE5FE09EE8662FLL;
    v22 = 0;

    for ( k = 0; k <= 343; ++k ) {
        /*** v972 defines which bit we are looking at now. ***/
        v972 = v23[k];

        /*** Encrypted "[...] Checking Flag %.2f%%\n" format string. ***/
        v20 = 0x24AD71BD93887E67LL;
        v21[0] = 0x235061D11E66C8A1LL;
        *(_QWORD *)((char *)v21 + 5) = 0xF025F752CE235061LL;
        *(_QWORD *)((char *)&v21[1] + 5) = 0xFE60420A4D3664LL;
        /*** Encryption key ***/
        v12 = 0x4CEE51E0BDA6503CLL;
        v13 = 0x657006BF770DABC4LL;
        v14 = 0x2B044AD5059033A2LL;
        v15 = 0x3F78BCC5FE6A672FLL;
        v16 = 0;

        /*** Decrypt the format string into v20. ***/
        for ( m = 0; m <= 27; ++m ) {
            v3 = *((unsigned __int8 *)&v12 + m % 32) ^ *((unsigned __int8 *)&v21[-1] + m);
            *((_BYTE *)&v21[-1] + m) ^= *((_BYTE *)&v12 + m % 32);
        }

        /*** Calculate current % progress. Note, we're dividing loop index by
             3.44 and the loop has 344 iterations. Hint, hint &#128578; ***/
        v7 = (double)k / 3.44;

        /*** This looks like a printf. ***/
        sub_40DE80((unsigned int)&v20, (_DWORD)a2, LODWORD(v7), v3, v4, v5, v11);

        /*** Encrypt the format string back. ***/
        for ( n = 0; n <= 27; ++n )
            *((_BYTE *)&v21[-1] + n) ^= *((_BYTE *)&v12 + n % 32);

        /*** Do something else with that % progress number. ***/
        sub_40DA00(&unk_417180, v7);


        /*** This is the interesting part. Remember, v972 is *bit* index. ***/

        v971 = v972 / 8;                    /*** Which byte are we looking at  ***/
        v970 = *(_BYTE *)(v972 / 8 + a1);   /*** Get that byte from input flag ***/
        v969 = v972 % 8;                    /*** Which bit are we looking at   ***/

        if ( (v970 & (1 << (v972 % 8))) <= 0 ) {
            /*** If the input flag bit was 0 ***/
            a2 = v963;
            /*** Run sub_401162 to check if it was valid in the flag. ***/
            if ( !(unsigned int)sub_401162((&v24)[2 * v972], v963, v964) ) {
              /*** If not, bail out. ***/
              v982 = 0; break;
            }
        } else {
            /*** If the input flag bit was 1 ***/
            a2 = v963;
            /*** Run sub_401162 to check if it was valid in the flag. ***/
            if ( !(unsigned int)sub_401162(v26[2 * v972 - 1], v963, v964) ) {
              /*** If not, bail out. ***/
              v982 = 0; break;
            }
        }
    }

    /*** At this point, we have either finished the loop with all correct bits,
         or bailed out at first incorrect one. v982 has that status. ***/
    if ( v982 ) {
        /*** Encrypted "[+] Flag Correct!" string ***/
        v18[0] = 0xCF4EA88C7128ACA1LL;
        v18[1] = 0x1298669FB40F9355LL;
        v19 = 12843821;
        /*** Encryption key. ***/
        v12 = 0xA82FC4CA517587FALL;
        v13 = 0x66FB03EDC660F075LL;
        v14 = 0x18BABBF41AC3F10CLL;
        v15 = 0xF5A0578F0914D17DLL;
        v8 = 152359293;
        v16 = 0;
        /*** Decrypt the string into v18. ***/
        for ( ii = 0; ii <= 18; ++ii ) {
            v3 = *((unsigned __int8 *)&v12 + ii % 32) ^ *((unsigned __int8 *)v18 + ii);
            v8 = v3;
            *((_BYTE *)v18 + ii) ^= *((_BYTE *)&v12 + ii % 32);
        }
        /*** Print it. ***/
        result = sub_40DE80((unsigned int)v18, (_DWORD)a2, v8, v3, v4, v5, v11);
        /*** Encrypt it back. ***/
        for ( jj = 0; jj <= 18; ++jj ) {
            result = jj;
            *((_BYTE *)v18 + jj) ^= *((_BYTE *)&v12 + jj % 32);
        }
    } else {
        /*** Encrypted "[+] Flag not correct." string ***/
        v17[0] = 0x5AC7A065DB154C1BLL;
        v17[1] = 0xF680368F5F16C5C3LL;
        v17[2] = 0xD5B05BD5548EE2LL;
        /*** Encryption key. ***/
        v12 = 0x3DA6CC23FB486140LL;
        v13 = 0x84EF55AF2B79ABE3LL;
        v14 = 0x84D5BA75A137EB90LL;
        v15 = 0xDC19985358EF5CD9LL;
        v10 = 1492081881;
        v16 = 0;
        /*** Decrypt the string into v17. ***/
        for ( kk = 0; kk <= 22; ++kk ) {
            v3 = *((unsigned __int8 *)&v12 + kk % 32) ^ *((unsigned __int8 *)v17 + kk);
            v10 = v3;
            *((_BYTE *)v17 + kk) ^= *((_BYTE *)&v12 + kk % 32);
        }
        /*** Print it. ***/
        result = sub_40DE80((unsigned int)v17, (_DWORD)a2, v10, v3, v4, v5, v11);
        /*** Encrypt it back. ***/
        for ( mm = 0; mm <= 22; ++mm ) {
            result = mm;
            *((_BYTE *)v17 + mm) ^= *((_BYTE *)&v12 + mm % 32);
        }
    }
    return result;
}
```

How did I get to all these insights in the comments? It is best to look at this
code backwards, starting at the big final `if (v982)` construct.

*   First, I decrypted all the strings using above Python snippets.
*   With that, the final `if(v982)` made it clear that semantics of `v982` is
    roughly `flag_was_correct`.
*   The only place we are reading from the input flag (the `a1` argument) is
    when setting `v970`. And the block of code following that looked like:
    *   Take the **bit** number `v972` from that flag (splitting `v972` into
        `v972 % 8` and `v972 / 8` parts).
    *   Depending if that bit is `0` or `1`, call `sub_401162` with slightly
        different arguments. Some of them pointing to that
        `large-array-of-int64s` manually initialized on top.
    *   And if that returns 0, it means that the bit in the flag was incorrect.
        Bail out.
*   The bits are not scanned linearly, but, in the order defined in `v23[344]`
    array, so, we can call it "permutation".
    *   See the `v972=v23[k]` at start of the `for(k=0,...` loop).
*   The `v23` array is initialized with a sequence of numbers first.
    *   Then, with a loop with 10000 iterations, its items are swapped based on
        results from `sub_40D2E0`.
    *   Which, together with its counterpart `sub_40D2D0` looks like a RNG,
        initialized in a typical `srand(time(0))` fashion.
*   The third encoded string is decrypted to `"[...] Checking Flag %.2f%%\n"`.
*   The `double k` variable is divided by `3.44`.
    *   And the loop has 344 iterations.
    *   And result of that division is used in the above format string &#128578;


## sub\_4012DB, but readable

The same idea expressed in more readable C, skipping the unimportant parts:

```c
#define FLAG_BITS (43 * 8)

void checkFlag(flag) {
    int large_array[LARGENUM];
    int permute[FLAG_BITS];
    int i, someval1, someval2;
    int flag_correct = 1;

    initialize_the_large_array(ouf, ouf, ouf);

    for (int i=0; i<FLAG_BITS; i++)
        permute[i]=i;

    srand(time(0));
    for (i=0; i<10000; i++) {
        int pos1 = rand() % FLAG_BITS;
        int pos2 = rand() % FLAG_BITS;
        int tmp = permute[pos1];
        permute[pos1] = permute[pos2];
        permute[pos2] = tmp;
    }

    for (i=0; i<FLAG_BITS; i++) {
        printf("[...] Checking Flag %.2f%%\n", (double)i/(FLAG_BITS/100.0));
        int bit = permute[i];
        if (flag[bit/8] & (1 << (bit%8))) {
            if (sub_401162(large_array[2*i], someval1, someval2)) {
                flag_correct = 0; break;
            }
        } else {
           if (sub_401162(large_array[2*i-1], someval1, someval2)) {
                flag_correct = 0; break;
           }
        }
    }
    if (flag_correct) putc("[+] Flag Correct!\n");
                 else putc("[+] Flag not correct.\n");
    return;
}
```

This starts to make sense. But we are still missing two things:

*   How about `large_array` (a.k.a `v24`)?
*   What is `sub_401162` doing?

## sub\_401162

Let's look at the function which determines whether a bit in the input flag was
correct.  It is called with arguments pointing somewhere into the `v24` pointer
array. IDA decompiles it to:

```c
__int64 __fastcall sub_401162(__int64 *a1, __int64 *a2, __int64 *a3) {
    char v4[1008];
    __int64 v5[1001];
    int v6, v7, v9;
    __int64 *v8;

    memset(v5, 0, 0x1F40uLL);
    v5[0] = (__int64)a1;
    memset(v4, 0, 0x3E8uLL);
    v9 = 76;
    v8 = a1;
    v7 = 0;
    v6 = 1;
    while (v6) {
        if (v9 == 76) {
            v8 = (__int64 *)*v8;
            v4[v7] = 76;
        } else {
            v8 = (__int64 *)v8[1];
            v4[v7] = 82;
        }
        v5[++v7] = (__int64)v8;
        if ( v8 == a2 )
              return 1LL;
        if ( v8 == a3 ) {
            if ( v9 == 76 ) {
                v8 = (__int64 *)v5[--v7];
                v9 = 82;
            } else {
                --v7;
                while ( v4[v7] == 82 ) {
                    if ( --v7 < 0 )
                        return 0LL;
                }
                v8 = (__int64 *)v5[v7];
                v9 = 82;
            }
        } else if ( v9 == 82 ) {
            v9 = 76;
        }
    }
    return 0LL;
}
```

# Breaking it

`sub_401162` *really* doesn't look like something we want to reverse-engineer,
especially as one of the inputs is yet another element that we don't understand
yet (`large_array`).

What other options do we have at this point?

## Key insight

*   **After each call to `sub_401162`, `AL==0` means that the bit in the flag was
    incorrect, `AL==1` otherwise.**
*   **And we know which bit (`v972`).**
*   **And we control the flag (`a1`).**

## The plan

1.  Send a flag full of zeros.
1.  Set a breakpoint after each of the `sub_401162` calls and record the
    result.
1.  After recording, change the result to 1, letting the loop continue
1.  At the end, reconstruct the flag from all the collected 344 bits.

Now, we probably don't want to do this manually. How about...

## The better plan

1.  Send a flag full of zeros.
1.  Initialize a 43-character buffer full of zeros, somewhere.
1.  After each of the two `sub_401162` calls, inject a shellcode, which will collect
    the *"input flag bit was correct"* statuses in the buffer.
1.  Patch the code to *not* bail out on incorrect bits. Just let the loop go
    through all 344 iterations.
1.  At the end, we would expect the buffer to be identical to the correct flag.
    Write it to `stdout`.

## Caveats

*   The bits in the flag are not verified in a linear order, but based on the
    permutation defined by the `v23[344]` array. But, we know which bit is
    currently processed (`[rbp-0x44]` a.k.a. `v972`) and we can grab the
    respective index from `v23[]`.
*   We need to *negate* the result of `sub_401162` (1==bad, 0==good), in order
    to get the actual bit set in the flag.
*   We need to overwrite the check that sets v982 to 0 on failure, letting the
    loop run until the end.

## Implementation

We will patch the binary with three pieces of code:

### 1. Allocate and zero a buffer

We need 43 bytes, filled with zeros.

*   **Where?** BSS ends at `41814F` but, looking at `/proc/self/maps`, the VM
    page ends at `419000`. So, should be OK to use the space from, say,
    `418200` as a buffer.
*   **Where do we put the shellcode?** Following all the decryption removals,
    we now have a large block of NOPs at the beginning of `sub_4012ED` - looks
    like a perfect spot.

    ```python
    # Initialize buffer
    init_collect = pwn.asm("""
        push  rax
        push  rdi
        push  rcx
        mov   rdi, 0x418200
        // <ESC>[1m<ESC>[32 (bright green)
        mov   rax, 0x32335B1B6D315B1B
        stosq
        mov   al,  'm'
        stosb
        xor   rax, rax
        mov   rcx, 43
        rep stosb
        // <ESC>[0m (reset)
        mov   rax, 0x00000A6D305B1B
        stosq
        pop   rcx
        pop   rdi
        pop   rax
        """)
    elf.write(0x4012ED, init_collect)
    ```

Just for fun &#128578; I added some extra terminal control codes to the
output, making it green. With these included, our *flag* buffer starts at
`0x418209` and *total length* of the final output is 57 bytes.

### 2. Collect the bits

We need to craft a shellcode which takes the currently processed bit index
(`[rbp-0x44]`), splits it into byte/bit indices and writes (negated) boolean
result of `sub_401162` (still in EAX) as a bit in the right position in the
buffer.

> **NOTE** See the inline comment: I don't know if this is a bug in `pwn`, but
> putting `[rbp-0x44]` there insisted on generating `[rbp-0x40]` instead. I
> empirically figured that putting `0x48` gets me what I want.

```python
# Collect bits from flag
collect_bit = pwn.asm("""
    // EAX has result of the bit check.
    push  rax
    push  rbx
    push  rcx
    xor   rbx,rbx
    xor   rcx,rcx
    // Note: this looks like pwntools error. It compiles to (correct) [rbp-0x44]
    mov   ecx,dword [rbp-0x48]
    mov   rbx,rcx
    and   rcx,7
    shr   rbx,3
    and   rax,1
    xor   rax,1
    shl   rax,cl
    or    byte ptr [0x418209+rbx], al
    pop   rcx
    pop   rbx
    pop   rax
    """)
```

We inject that code after both returns from `sub_401162`. Conveniently, this
also overwrites the conditional code, that bails out if the bit comparison did
not match the flag.

```python
elf.write(0x40B796, collect_bit)
elf.write(0x40B893, collect_bit)
```

### 3. Print the result

Assuming all above code works as expected, all that is left is to get the
result out in some form. Again, conveniently, at `40BE64` we have a long batch
of `NOP`s after returning from `sub_4012DB`.  Let's put it there

```python
print_flag = pwn.asm("""
    push  rax
    push  rdx
    push  rdi
    mov   rax, 1
    mov   rdi, 1
    mov   rsi, 0x418200
    mov   rdx, 57
    syscall
    pop   rdi
    pop   rdx
    pop   rax
    """)
elf.write(0x40BE64, print_flag)
```

## Execution

*   Save the modified binary:

    ```python
    if os.path.exists('train_debug'):
      os.unlink('train_debug')
    elf.save('train_debug')
    os.chmod('train_debug', 0o755)
    ```

*   Execute, collect output:

    ```python
    io = pwn.process('./train_debug')
    io.sendline(b'\x00'*43+b'\x0A')
    while True:
      try:
        print(io.readline().decode("ascii"), end="")
      except EOFError:
        break
    ```

*   Result:

    > ```bash
    > [+] Starting local process './train_debug': pid 197559
    > << Train >>
    > > Flip the switches!
    > [+] Flag: [...] Checking Flag 0.00%
    > [...] Checking Flag 0.29%
    > [...] Checking Flag 0.58%
    >       ····················
    > [...] Checking Flag 99.42%
    > [...] Checking Flag 99.71%
    > [+] Flag correct!
    > shc2024{ch00_ch00_tr41n_on_tr4ck_ch00_ch00}
    > [*] Process './train_debug' stopped with exit code 18 (pid 197559)
    > ```

&#x1F389; &#x1F389; &#x1F389; &#x1F389; &#x1F389; &#x1F389; &#x1F389; &#x1F389;
&#x1F389; &#x1F389; &#x1F389; &#x1F389; &#x1F389; &#x1F389; &#x1F389; &#x1F389;
&#x1F389; &#x1F389; &#x1F389; &#x1F389; &#x1F389; &#x1F389; &#x1F389; &#x1F389;
&#x1F389; &#x1F389; &#x1F389; &#x1F389; &#x1F389; &#x1F389; &#x1F389; &#x1F389;

## The flag

```
shc2024{ch00_ch00_tr41n_on_tr4ck_ch00_ch00}
```

## Verification

Entering the above flag into the original binary confirmed that it is correct:

> ```bash
> $ ./train
> << Train >>
> > Flip the switches!
> [+] Flag: shc2024{ch00_ch00_tr41n_on_tr4ck_ch00_ch00}
> [...] Checking Flag 0.00%
> [...] Checking Flag 0.29%
>       ····················
> [...] Checking Flag 99.42%
> [...] Checking Flag 99.71%
> [+] Flag correct!
> ```

# Complete exploit

```python
#!/usr/bin/python3
import os
import pwn

pwn.context(arch='amd64', os='linux')
elf = pwn.ELF('train')
MODIFIED_BINARY='train_debug'


##################
# HELPER FUNCTIONS

# Decrypt an area in the code, using given set of four 64-bit keys.
def decode(start, length, key):
  for i in range(length):
    elf.p8(start+i, elf.u8(start+i)^((key[(i>>3)&0x03]>>((i&0x07)<<3))&0xFF))

# Simple helper function to fill the area with NOPs.
def nopify(start, endplus1):
  for i in range(start, endplus1):
    elf.p8(i, 0x90)


############################
# DISABLE DEBUGGER DETECTION

elf.write(0x410A74, pwn.asm("""mov rax,1 ; ret"""))
nopify(0x410A7C, 0x410AED)

###################
# DECRYPT FUNCTIONS

# 40C661 decrypts 40BECB(1941b)
decode(0x40BECB,1941,[0x9611CA82CA876936,0x56AF10461907E232,0xBE4C5F1B7D607FAF,0xC8F28DAD0873AAD7])
nopify(0x40C7C0,0x40C868)
nopify(0x40C892,0x40C8D4)
# 40BECB decrypts/calls/encrypts 40CCCF(669b), twice
decode(0x40CCCF,669,[0xE4E0C840E45018D6,0xC26835F135A43917,0xF70CF805EF4D4C1A,0x44FC8C8E48523841])
nopify(0x40BEDD,0x40BF73)
nopify(0x40BF7D,0x40BFD7)
nopify(0x40C48A,0x40C4E9)
nopify(0x40C4EE,0x40C548)
# 40BECB decrypts/calls 40C925(937b)
decode(0x40C925,937,[0xF84DF81EDF4BAC2A,0x9812AF0F26AC6587,0xBA7165DB8E9F1578,0x4E7B55C2B7E4E2C3])
nopify(0x40BFD7,0x40C076)
# 40C925 decrypts/calls/encrypts 40C8D6(40b)
decode(0x40C8D6,40,[0xFED54656EF81D92F,0x768CD52E82F6E61B,0xC099F7C58956F861,0x678571C1C98EF7CB])
nopify(0x40CA62,0x40CB07)
nopify(0x40CB13,0x40CB6D)
# 40C925 decrypts/calls/encrypts 40C8FF(37b)
decode(0x40C8FF,37,[0x126D01E982E6C01,0xEF83A049716A980B,0x74DE05C018549D54,0x856BA5BA83CA7184])
nopify(0x40CBB5,0x40CC57)
nopify(0x40CC61,0x40CCBB)
# 40BECB decrypts/calls 401139(40b), twice
decode(0x401139,40,[0xC08503C38F86CFDF,0xB3DA8E0B0B088682,0xE1863958E689FC6D,0x739F2DFA39ACC3F3])
nopify(0x40C151,0x40C1F6)
nopify(0x40C205,0x40C25F)
nopify(0x40C379,0x40C3D3)
nopify(0x40C3E2,0x40C43C)
# 40BECB decrypts/calls 40BB7C(846b)
decode(0x40BB7C,846,[0x52BFED41B50892C5,0xC8B3B529FDD13057,0x46B64558D4CE8336,0x55FA11C3B3980043])
nopify(0x40C548,0x40C5F0)
nopify(0x40C5FA,0x40C657)
# 40BB7C decrypts/calls/encrypts 40CCCF(669b). It's already decrypted! (above)
nopify(0x40BCA1,0x40BD49)
nopify(0x40BD53,0x40BDB0)
# 40BB7C decrypts/calls/encrypts 4012DB(43168b)
decode(0x4012DB,43168,[0xF989557D9488AC9B,0xC2076EEBF34552C1,0x5493D088FC52101D,0x347B90473EC69E9E])
nopify(0x40BDB0,0x40BE58)
nopify(0x40BE64,0x40BEC1)
# 4012DB decrypts/calls/encrypts 40CCCF(669b), twice. It's already decrypted! (above)
nopify(0x4012F4,0x401393)
nopify(0x40139D,0x4013FA)
nopify(0x40B808,0x40B865)
nopify(0x40B8A0,0x40B8FD)
# 4012DB decrypts/calls/encrypts 401162(376b).
decode(0x401162,376,[0xF35E59A421044432,0xAF609CF5C7C65071,0x55E109DF495F6009,0xE8FE5FE09EE8662F])
nopify(0x40B70B,0x40B768)
nopify(0x40B7A6,0x40B803)


################
# OPTIONAL PARTS

# - Disable making text segment R/W
nopify(0x40C66C, 0x40C7C0)

# - Disable 40CCCF altogether
elf.write(0x40CCCF, pwn.asm("""mov rax,0; ret"""))
nopify(0x40CCD8, 0x40CF6C)

# - Disable curl
nopify(0x411AB1, 0x411AE9)


#########
# EXPLOIT

# Initialize buffer
init_collect = pwn.asm("""
    push  rax
    push  rdi
    push  rcx
    mov   rdi, 0x418200
    // <ESC>[1m<ESC>[32 (bright green)
    mov   rax, 0x32335B1B6D315B1B
    stosq
    mov   al,  'm'
    stosb
    xor   rax, rax
    mov   rcx, 43
    rep stosb
    // <ESC>[0m (reset)
    mov   rax, 0x00000A6D305B1B
    stosq
    pop   rcx
    pop   rdi
    pop   rax
    """)
elf.write(0x4012ED, init_collect)

# Collect bits from flag
collect_bit = pwn.asm("""
    // EAX has result of the bit check.
    push  rax
    push  rbx
    push  rcx
    xor   rbx,rbx
    xor   rcx,rcx
    // Note: this looks like pwntools error. It compiles to (correct) [rbp-0x44]
    mov   ecx,dword [rbp-0x48]
    mov   rbx,rcx
    and   rcx,7
    shr   rbx,3
    and   rax,1
    xor   rax,1
    shl   rax,cl
    or    byte ptr [0x418209+rbx], al
    pop   rcx
    pop   rbx
    pop   rax
    """)
elf.write(0x40B796, collect_bit)
elf.write(0x40B893, collect_bit)

# Print the flag
print_flag = pwn.asm("""
    push  rax
    push  rdx
    push  rdi
    mov   rax, 1
    mov   rdi, 1
    mov   rsi, 0x418200
    mov   rdx, 57
    syscall
    pop   rdi
    pop   rdx
    pop   rax
    """)
elf.write(0x40BE64, print_flag)


########
# RUN IT

# Save the modified binary
if os.path.exists(MODIFIED_BINARY):
  os.unlink(MODIFIED_BINARY)
elf.save(MODIFIED_BINARY)
os.chmod(MODIFIED_BINARY, 0o755)

# Execute the modified binary
io = pwn.process('./'+MODIFIED_BINARY)
# Send flag full of zeros
io.sendline(b'\x00'*43+b'\x0A')
# Collect outputs
while True:
  try:
    print(io.readline().decode("ascii"), end="")
  except EOFError:
    break

```

# Some more random musings

## <a name="sigcld"></a>About that SIGCLD

As mentioned above, initial attempt at debugging the program with IDA results
with a `SIGCLD` dialog window at some point.  We ignored it back then (and were
able to solve the challenge), but, let's dig into it more.

That signal means that there were some child processes spawned. And indeed:

```bash
$ strace -t -f -s 128 ./train_debug  2>&1 | grep -E 'fork|exec'
11:44:26 execve("./train_debug", ["./train_debug"], 0x7ffd16f74980 /* 81 vars */) = 0
[pid 213174] 11:44:26 execve("/bin/sh", ["sh", "-c", "curl -X POST https://mnt.gk.wtf/hypecounter.php 2> /dev/null > /dev/null"], 0x7ffe3f892428 /* 81 vars */ <unfinished ...>
[pid 213174] 11:44:26 <... execve resumed>) = 0
[pid 213175] 11:44:26 execve("/usr/bin/curl", ["curl", "-X", "POST", "https://mnt.gk.wtf/hypecounter.php"], 0x5611f6e98e40 /* 81 vars */) = 0
[pid 213177] 11:44:27 execve("/bin/sh", ["sh", "-c", "curl -X POST https://mnt.gk.wtf/hypecounter.php 2> /dev/null > /dev/null"], 0x7ffe3f892428 /* 81 vars */ <unfinished ...>
[pid 213177] 11:44:27 <... execve resumed>) = 0
[pid 213178] 11:44:27 execve("/usr/bin/curl", ["curl", "-X", "POST", "https://mnt.gk.wtf/hypecounter.php"], 0x563c36f5de40 /* 81 vars */) = 0
[pid 213180] 11:44:28 execve("/bin/sh", ["sh", "-c", "curl -X POST https://mnt.gk.wtf/hypecounter.php 2> /dev/null > /dev/null"], 0x7ffe3f892428 /* 81 vars */ <unfinished ...>
[pid 213180] 11:44:28 <... execve resumed>) = 0
[pid 213181] 11:44:28 execve("/usr/bin/curl", ["curl", "-X", "POST", "https://mnt.gk.wtf/hypecounter.php"], 0x55685a75ae40 /* 81 vars */) = 0
[pid 213183] 11:44:29 execve("/bin/sh", ["sh", "-c", "curl -X POST https://mnt.gk.wtf/hypecounter.php 2> /dev/null > /dev/null"], 0x7ffe3f892428 /* 81 vars */ <unfinished ...>
[pid 213183] 11:44:29 <... execve resumed>) = 0
[pid 213184] 11:44:29 execve("/usr/bin/curl", ["curl", "-X", "POST", "https://mnt.gk.wtf/hypecounter.php"], 0x5644000f6e40 /* 81 vars */) = 0
[pid 213186] 11:44:30 execve("/bin/sh", ["sh", "-c", "curl -X POST https://mnt.gk.wtf/hypecounter.php 2> /dev/null > /dev/null"], 0x7ffe3f892428 /* 81 vars */ <unfinished ...>
[pid 213186] 11:44:30 <... execve resumed>) = 0
[pid 213187] 11:44:30 execve("/usr/bin/curl", ["curl", "-X", "POST", "https://mnt.gk.wtf/hypecounter.php"], 0x562862867e40 /* 81 vars */) = 0
```

There seems to be a separate thread, which calls `sh -c curl -X POST
https://mnt.gk.wtf/hypecounter.php 2> /dev/null > /dev/null` every second, while
waiting for user input.

I remembered seeing this URL in other challenges too - it is a simple counter
and all results apart from the exit code are being discarded here. So, almost
certainly a distraction. Still, annoying. Let's get rid of it.

### Stopping the Hype Counter

**Observation**: already earlier, I noticed that after ignoring the `SIGCLD`,
IDA had two entries in the `Threads` window.

Remember how we found the first encrypted routine: step through the (new
decrypted) chain of CALLs, until something happens.  Let's use that to catch
the moment when that new thread appears in IDA:

*   Entering `sub_40C661`: there is still one thread. New one appears after
    `call sub_40BECB` at `40C86D`.
    *   Inside `sub_40BECB`, the new thread appears after `call sub_411220` at
        `40C091`.
        *   That `sub_411220` looks a bit too annoying to analyze. But, let's
            look at the state of the new thread that appeared **right after**
            return from `sub_411220`:

            ```asm
            .text:0000000000411AB1 sub_411AB1      proc near
            .text:0000000000411AB1 child_tid       = qword ptr  8
            .text:0000000000411AB1          xor     eax, eax
            .text:0000000000411AB3          mov     al, 38h ; '8'
            .text:0000000000411AB5          mov     r11, rdi
            .text:0000000000411AB8          mov     rdi, rdx        ; clone_flags
            .text:0000000000411ABB          mov     rdx, r8         ; parent_tid
            .text:0000000000411ABE          mov     r8, r9
            .text:0000000000411AC1          mov     r10, [rsp+child_tid] ; child_tid
            .text:0000000000411AC6          mov     r9, r11
            .text:0000000000411AC9          and     rsi, 0FFFFFFFFFFFFFFF0h
            .text:0000000000411ACD          sub     rsi, 8          ; newsp
            .text:0000000000411AD1          mov     [rsi], rcx
            .text:0000000000411AD4          syscall                 ; LINUX - sys_clone
                                            <<<RIP points here>>>
            .text:0000000000411AD6          test    eax, eax
            .text:0000000000411AD8          jnz     short locret_411AE9
            .text:0000000000411ADA          xor     ebp, ebp
            .text:0000000000411ADC          pop     rdi
            .text:0000000000411ADD          call    r9
            .text:0000000000411AE0          mov     edi, eax        ; error_code
            .text:0000000000411AE2          xor     eax, eax
            .text:0000000000411AE4          mov     al, 3Ch ; '<'
            .text:0000000000411AE6          syscall                 ; LINUX - sys_exit
            .text:0000000000411AE8          hlt
            .text:0000000000411AE9 locret_411AE9:
            .text:0000000000411AE9          ret
            ```

IDA provides enough hints, that we can easily decompile this by hand:

```c
sub_411AB1(rdi, rsi, rdx, rcx) {
  pid = sys_clone(<<< some flags, based on the arguments >>>);
  if (!pid) {
     <<< call the address passed as first argument >>>
     sys_exit();
  }
  return pid;
}
```

Let's just replace it with nops, all the way to the final `RET`:

```python
nopify(0x411AB1, 0x411AE9)
```

Success! No more extra processes in the `strace -f` output - and `SIGCLD`
warning in IDA is gone too &#128512;


## <a name="antidebug"></a>About that debugger detection

My initial bypass of the debugger detection was a bit of a hack. Once I had all
the code decrypted, I figured that `sub_40CCCF` was the full _"debugger
protection"_ function and I could just change it to an empty one.  I verified
this later by

*   Removing that `mov rax,0; ret` hack from the first step in the write-up
*   Replacing `decode(0x40CCCF,669,...)` with
    `elf.write(0x40CCCF, pwn.asm("""mov rax,0; ret"""))`

... and the code was still running fine and fully debuggable. Note that we
still need to decrypt `sub_40C661` / `sub_40BECB` first - and disable all the
places where `sub_40CCCF` is decrypted/encrypted!


## <a name="symbols"></a>Some other symbols that I identified

... or I *thought* I identified:

*   `401000: _init_proc`
*   `40D2D0: srand`
*   `40D2E0: rand`
*   `40DB70: fgets`
*   `40DE80: printf`
*   `411AB1: clone`
*   `411F60: stack_smashing_error`
*   `413CD0: mmap`
*   `413DC0: mprotect`
*   `413E10: munmap`
*   `414AC0: read`
*   `415B20: execve`
*   `415D5C: _term_proc`

---

## `shc2024{ch00_ch00_tr41n_on_tr4ck_ch00_ch00}`


<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
