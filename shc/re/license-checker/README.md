# license-checker

[library.m0unt41n.ch/challenges/license-checker](https://library.m0unt41n.ch/challenges/license-checker) ![](../../resources/re.svg) ![](../../resources/baby.svg) 

# TL;DR

We get a binary that has the flag encrypted somewhere inside:

```
$ ./license-checker 
Enter the input: asdf 
Oops, wrong license.
But hey, no biggie, it's practically uncrackable!
```

# Decompilation

First there are three somewhat complex functions that print the flag... but we don't care about
their details &#128578; as long as we can call them

```c
void b(char *in, int len, char *userKey, char *ivec) {
    (...)
}

void a() {
    (...)
}
```

Then, the actually meaningful part:

```c
void encryptInput(char *str) {
  for ( int i = 0; i < strlen(str); ++i )
    str[i] ^= 0x18u;
}

void hexEncode(char *src, char *dst) {
  for ( int i = 0; i < strlen(src); ++i )
    sprintf(&dst[2 * i], "%02X", src[i]);
  dst[2 * strlen(src)] = 0;
}

int compareInputToLicense(const char *str) {
  return strcmp(str, "542E2C21355A592829352828212A35592F295A") == 0;
}

unsigned int verifyInput(char *input) {
  char vec[8];

  encryptInput(input);
  size_t hexStrLen = 2 * strlen(input);
  char *hexStr = alloca(16 * ((2 * strlen(input) + 16) / 16));
  char *dst = vec;
  hexEncode(input, vec);
  return compareInputToLicense(dst);
}

int main(int argc, const char **argv, const char **envp) {
  char input[112]; // [rsp+0h] [rbp-70h] BYREF

  printf("Enter the input: ");
  scanf("%s", input);
  if ( verifyInput(input) )
    a();
  else
    puts("Oops, wrong license.\nBut hey, no biggie, it's practically uncrackable!");
  return 0;
}
```

# Analysis

*   `verifyInput()` takes user input
*   Calls `encryptInput()`, which XORs the string with `0x18`
*   Calls `hexEncode()` which, well, hex encodes
*   And finally, calls `compareInputToLicense()`, which compares the result to a hardcoded hex string.

Using
[CyberChef](https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')XOR(%7B'option':'Hex','string':'18'%7D,'Standard',false)&input=NTQyRTJDMjEzNTVBNTkyODI5MzUyODI4MjEyQTM1NTkyRjI5NUE),
we decode that string to `L649-BA01-0092-A71B`. And then, running the program gets the flag:

```
$ ./license-checker 
Enter the input: L649-BA01-0092-A71B
Congratulations, you cracked it!
Flag{Cracked_XOR_Like_An_Eggshell}
```

---

## `Flag{Cracked_XOR_Like_An_Eggshell}`


<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
