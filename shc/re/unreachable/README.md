# unreachable

[library.m0unt41n.ch/challenges/unreachable](https://library.m0unt41n.ch/challenges/unreachable) ![](../../resources/re.svg) ![](../../resources/baby.svg) 

# TL;DR

We are given a binary that decompiles to:

```c
char encrypted_flag[48] = {
  0x7F, 0xC1, 0xBE, 0x0D, 0x1B, 0x0E, 0xEF, 0x0E,
  0xC0, 0xD7, 0x78, 0xDA, 0x9E, 0xD2, 0x68, 0x25,
  0xC0, 0xAF, 0x1F, 0x45, 0x10, 0xD6, 0x9F, 0x8A,
  0x5B, 0xD4, 0x6F, 0x5C, 0xEA, 0x40, 0xFE, 0xE6,
  0x1A, 0x5E, 0xA5, 0x2C, 0xD8, 0xF7, 0x0A, 0x32,
  0x9D, 0xE2, 0xC4, 0x99, 0x13, 0xBF, 0x88, 0xDD
}

void printflag() {
  char key[256];
  char ivec[16];
  char flag[48];
  
  memset(flag, 0, 48);
  qmemcpy(ivec, "initialvector123", sizeof(ivec));
  AES_set_decrypt_key(key, 128, key);
  AES_cbc_encrypt(&encrypted_flag, flag, 48, key, ivec, 0);
  printf("Flag: %s\n", flag);
}

int main(int argc, const char **argv, const char **envp) {}
  char str[4];
  strcpy(str, "123");
  if ( !strcmp(str, "321") )
    printflag();
  else
    puts("Hehe, no flag for you :3");
  return 0;
}
```

The easiest way around it: hexedit the binary, replacing `123` string with `321` &#128578;

---

## `SCD{h0w_y0u_5h01dnt_b3_h3r3_81d6cdaa}`


<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
