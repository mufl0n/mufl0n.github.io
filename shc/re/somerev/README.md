# somerev

[library.m0unt41n.ch/challenges/somerev](https://library.m0unt41n.ch/challenges/somerev) ![](../../resources/re.svg) ![](../../resources/easy.svg) 

# TL;DR

The flag is encrypted in the code - and, in order to print it, one just needs to bypass a simple check &#128578;

# The code

Initial disassembly with IDA doesn't look too complicated:

```c
__int64 __fastcall main(int a1, char **a2, char **a3) {
  unsigned __int64 input; // rax
  __int64 i; // rax
  __int64 v5; // rbx
  __int64 buf; // [rsp+8h] [rbp-40h] BYREF
  char format[16]; // [rsp+13h] [rbp-35h] BYREF
  __int128 v9; // [rsp+23h] [rbp-25h]
  char H5_t[8]; // [rsp+33h] [rbp-15h] BYREF

  *(_OWORD *)format = *(_OWORD *)&xmmword_5555555545F0;
  v9 = *(_OWORD *)&xmmword_555555554600;
  strcpy(H5_t, "H5 t");
  puts("Password:");
  buf = 0LL;
  input = read(0, &buf, 7uLL);
  if ( input > 7 )
    passOver7();
  format[input - 5] = 0;
  if ( (_DWORD)buf == 'hslu' )
  {
    puts("Access granted");
    for ( i = 0LL; i != 36; ++i )
      format[i] ^= aUlsh[i & 3] ^ i ^ 0x42;
    v5 = 0LL;
    printf("Flag: ");
    printf(format);
  }
  else
  {
    puts("Access denied");
    return -1LL;
  }
  return v5;
}
```

But, before I even started looking at it more seriously, I just ran it under the debugger, got to the point of...

```bash
.text:0000555555555860                 mov     byte ptr [rsp+rax+48h+buf], 0
.text:0000555555555865                 cmp     dword ptr [rsp+48h+buf], 68736C75h
.text:000055555555586D  >>>>>>>>>>>>>  jnz     short loc_5555555558AA
.text:000055555555586F                 lea     rdi, aAccessGranted ; "Access granted"
.text:0000555555555876                 call    cs:puts_ptr
.text:000055555555587C                 xor     eax, eax
```

... and flipped the `ZF` to one &#128512;

BTW, looking at the code, it's fairly obvious that the password is `ulsh`

---

## `stairctf{r3v_c4n_b3_pr3tty_fun!!_:3}`


<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
