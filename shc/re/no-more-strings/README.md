# no-more-strings

[library.m0unt41n.ch/challenges/no-more-strings](https://library.m0unt41n.ch/challenges/no-more-strings) ![](../../resources/re.svg) ![](../../resources/baby.svg) 

# TL;DR

The flag is hidden in a binary - and in order to get it, we have to provide
a correct password.

# Code

```c
char xored_pass[] = "UihrHrLxRtqdsRdbsduQ`rrve";
char xored_flag[28] = {
    0x07, 0x2B, 0x2D, 0x08, 0x31, 0x43, 0x3F, 0x26, 0x67, 0x44, 0x1E, 0x11, 0x2D, 0x27,
    0x0D, 0x57, 0x06, 0x3A, 0x1C, 0x64, 0x13, 0x17, 0x49, 0x44, 0x19, 0x00, 0x00, 0x00
};
int pass_len = 25;

int main(int argc, const char **argv, const char **envp) {
  char input[104];
  printf("Enter the password: ");
  scanf("%99s", input);
  int correct = 1;
  for ( int i = 0; i < pass_len; ++i ) {
    if ( ((unsigned __int8)xored_pass[i] ^ input[i]) != 1 ) {
      correct = 0; break;
    }
  }
  if ( correct ) {
    printf("Correct password! Here is your flag: ");
    for ( int j = 0; j < pass_len; ++j )
      putchar(xored_flag[j] ^ input[j]);
    putchar('\n');
  }  else {
    puts("Incorrect password.");
  }
  return 0;
}
```

# Analysis

This is a simple decompilation exercise. The user input needs to match `xorred_pass ^ 0x01`.
[CyberChef says](https://gchq.github.io/CyberChef/#recipe=XOR(%7B'option':'Hex','string':'1'%7D,'Standard',false)&input=VWlockhyTHhSdHFkc1JkYnNkdVFgcnJ2ZQ)
this means: `ThisIsMySuperSecretPasswd`. Providing that as the input will decrypt the flag.

---

## `SCD{x0r_41nt_th4t_h4rd:3}`


<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
