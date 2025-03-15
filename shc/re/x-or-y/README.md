# x-or-y

[library.m0unt41n.ch/challenges/x-or-y](https://library.m0unt41n.ch/challenges/x-or-y) ![](../../resources/re.svg) ![](../../resources/easy.svg) 

# TL;DR

We get a simple binary, to decompile and find the flag inside

# Decompiled code

```c
int main(int argc, const char **argv, const char **envp) {
  char encryptedPassword[32], input[40];
  
  *(long *)encryptedPassword = 0x24A4B494B1A110ALL;
  *(long *)&encryptedPassword[8] = 0x110D261E17104C2CLL;
  *(long *)&encryptedPassword[16] = 0x49261D49491E264ALL;
  *(int *)&encryptedPassword[24] = 0x1261D15;
  *(short *)&encryptedPassword[28] = 0xB49;
  encryptedPassword[30] = 4;

  printf("Enter the password to continue: ");
  fgets(input, 32, stdin);
  int correct = 1;
  for ( int i = 0; i <= 30; ++i )
    correct = ((input[i] ^ 0x79) == encryptedPassword[i]) & correct;
  if ( correct == 1 ) {
    puts("This password is correct.");
    puts("Have a nice day!");
  } else {
    puts("Sorry, this password is wrong :(");
  }
  return 0;
}
```

The flag is stored in the `encryptedPassword` byte array, XORed with `0x79`. We can get the it with
[CyberChef](https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')XOR(%7B'option':'Hex','string':'0x79'%7D,'Standard',false)&input=MEExMTFBNEI0OTRCNEEwMgoyQzRDMTAxNzFFMjYwRDExCjRBMjYxRTQ5NDkxRDI2NDkKMTUxRDI2MDEKNDkwQgowNAo)

---

## `shc2023{U5ing_th3_g00d_0ld_x0r}`


<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
