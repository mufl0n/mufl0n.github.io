# winning-argument

[library.m0unt41n.ch/challenges/winning-argument](https://library.m0unt41n.ch/challenges/winning-argument) ![](../../resources/re.svg) ![](../../resources/easy.svg) 

# TL;DR

We are given an executable, which internally has a flag, encrypted with a simple XOR
against `argv[0]` (modulo string length).

# Solution

## The code

IDA disassembly, slightly annotated.

```c
char encryptedKey[] = {
  0x14, 0x59, 0x1b, 0x00, 0x1d, 0x07, 0x09, 0x4a, 0x3e, 0x14, 0x15, 0x45, 0x00,
  0x3a, 0x5e, 0x2b, 0x1e, 0x1a, 0x31, 0x0d, 0x05, 0x5d, 0x53, 0x5f, 0x0d, 0x0b,
  0x38, 0x06, 0x18, 0x15, 0x5d, 0x06, 0x1e, 0x59, 0x1c, 0x4f, 0x00
};

__int64 __fastcall main(int argc, char **argv, char **envp) {
  int i; // [rsp+1Ch] [rbp-14h]
  int exeNameLen; // [rsp+20h] [rbp-10h]
  int arg1Len; // [rsp+24h] [rbp-Ch]
  char *argCopy; // [rsp+28h] [rbp-8h]

  *argv = __xpg_basename(*argv);
  if ( argc > 1 ) {
    exeNameLen = strlen(*argv);
    arg1Len = strlen(argv[1]);
    argCopy = strdup(argv[1]);
    for ( i = 0; i < arg1Len; ++i )
      argCopy[i] ^= (*argv)[i % exeNameLen];
    if ( !memcmp(argCopy, &encryptedKey, 0x25uLL) ) {
      puts("Congratulations, you have won the argument!");
      printf("Here is your flag: shc2024{%s}\n", argv[1]);
    } else {
      puts("Try bringing better arguments.");
      puts("The current ones don't convince anybody.");
    }
    return 0LL;
  } else {
    printf("Usage: %s <input>\n", *argv);
    return 1LL;
  }
}
```

## Decryption

```python
#!/usr/bin/python

key = [ 0x14, 0x59, 0x1b, 0x00, 0x1d, 0x07, 0x09, 0x4a, 0x3e,
        0x14, 0x15, 0x45, 0x00, 0x3a, 0x5e, 0x2b, 0x1e, 0x1a,
        0x31, 0x0d, 0x05, 0x5d, 0x53, 0x5f, 0x0d, 0x0b, 0x38,
        0x06, 0x18, 0x15, 0x5d, 0x06, 0x1e, 0x59, 0x1c, 0x4f,
        0x00 ]

name = 'winning-argument'

print("shc2024{", end="")
for i in range(len(key)-1):
  print(chr(key[i] ^ ord(name[i % len(name)])), end="")
print("}")
```

---

## `shc2024{c0unting_fr0m_0_is_cl34rly_sup3ri0r!}`


<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
