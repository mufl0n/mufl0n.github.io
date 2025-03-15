# time-capsule

[library.m0unt41n.ch/challenges/time-capsule](https://library.m0unt41n.ch/challenges/time-capsule) ![](../../resources/re.svg) ![](../../resources/easy.svg) 

# TL;DR

We get a Go binary, which prints the flag. Just... after a very very long time.

# Decompiled code

This has quite a bit of casts and other boilerplate removed for readability:

```c
int main_getFlag() {
  char flag[23];
  void *strObj1[2], *strObj2[2];

  flag[0] = 0xB0;
  *(short *)&flag[1] = 0xD78;
  *(int *)&flag[3] = 0x6C01E54B;
  *(long *)&flag[7] = 0x1F11CD1D3DCD1D93LL;
  *(long *)&flag[15] = 0x581FFA8FCD8F431DLL;

  int nexti = 0;
  for ( int i = 0; i < 52560000; i = nexti + 1 ) {
    for ( int j = 0; j < 23; ++j ) {
      char b = flag[j] ^ 0x42;
      flag[j] = b;
      flag[j] = i + __ROL1__(b, 7);
    }
    nexti = i;
    time_Sleep(1000000000);
  }

  strObj1[0] = &RTYPE_string;
  strObj1[1] = &ptrFlag;   // "Flag:"
  strObj2[0] = &RTYPE_string;
  strObj2[1] = runtime_convTstring(runtime_slicebytetostring(0, flag, 23), flag);;
  return fmt_Fprintln(&go_itab__ptr_os_File_comma_io_Writer, os_Stdout, strObj1);
}

void main_main() {
  void *strObj1[2], *strObj2[2];

  strObj1[0] = &RTYPE_string;
  strObj1[1] = &ptrWelcome1;  // "Welcome to the time capsule."
  fmt_Fprintln(&go_itab__ptr_os_File_comma_io_Writer, os_Stdout, strObj1);
  strObj2[0] = &RTYPE_string;
  strObj2[1] = &ptrWelcome2;  // "The capsule will automatically open in 100 years."
  fmt_Fprintln(&go_itab__ptr_os_File_comma_io_Writer, os_Stdout, strObj2);
  main_getFlag();
}
```

# Analysis

This seems to be starting with storing the encrypted text in `flag` array and then, doing
some fun, double-nested iteration over it, to decode it. With a long delay in-between.

The most obvious solution is to remove the delay (either with NOPs or by making the
argument zero). But, for some reason, I could not get that to work within minutes.

So, I went for a short C program that just does the same thing as above code &#128578;

# Getting the flag

```c
#include <stdio.h>

unsigned char enc[24] = {
  0xB0, 0x78, 0x0D, 0x4B, 0xE5, 0x01, 0x6C, 0x93,
  0x1D, 0xCD, 0x3D, 0x1D, 0xCD, 0x11, 0x1F, 0x1D,
  0x43, 0x8F, 0xCD, 0x8F, 0xFA, 0x1F, 0x58, 0x00
};

int main(void) {
  for (int i=0; i<52560000; i++) {
    for (int j=0; j<23; j++) {
      char b = enc[j]^0x42;
      if (b&0x01) b = (b>>1)+128;
             else b = (b>>1);
      b += (i & 0xFF);
      enc[j] = b;
    }
  }
  printf("%s\n", enc);
}
```

The only interesting thing here is: we have to implement the `__ROL1__`, which
implements the `ROL` instruction of the x86 assembly
([link](https://www.aldeid.com/wiki/X86-assembly/Instructions/rol)).

---

## `SCD{b4ck_t0_th3_futur3}`


<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
