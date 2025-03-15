# distraction

[library.m0unt41n.ch/challenges/distraction](https://library.m0unt41n.ch/challenges/distraction) ![](../../resources/re.svg) ![](../../resources/baby.svg) 

# TL;DR

This is a baby exercise in decompilation. Putting the provided binary into IDA gets us:

```c
char unk_201B[29] = {
    0x12, 0x07, 0x07, 0x28, 0x1F, 0x70, 0x0B, 0x1B,
    0x58, 0x41, 0x03, 0x33, 0x3E, 0x41, 0x01, 0x01,
    0x31, 0x2B, 0x59, 0x41, 0x31, 0x47, 0x33, 0x0E,
    0x53, 0x46, 0x19, 0x2D, 0x00
};
char encryptedFlag[] = "ADCS{Cht512__50n_tht_3lfg4}P";

int main(int argc, const char **argv, const char **envp) {
  unsigned int i;       // [rsp+Ch]  [rbp-64h]
  char xor_result[29];  // [rsp+10h] [rbp-60h] BYREF
  char input[50];       // [rsp+30h] [rbp-40h] BYREF

  printf("Enter the flag: ");
  fgets(input, 50, _bss_start);
  input[strcspn(input, "\n")] = 0;
  for ( i = 0; i < 29; ++i )
    xor_result[i] = encryptedFlag[i] ^ input[i];
  if ( !memcmp(xor_result, &unk_201B, 29) )
    puts("Congratulations, the flag is correct!");
  else
    puts("Sorry, the flag is incorrect.");
  return 0;
}
```

The flag is a
[simple XOR of both buffers](https://gchq.github.io/CyberChef/#recipe=XOR(%7B'option':'Hex','string':'120707281F700B1B584103333E410101312B59413147330E5346192D00'%7D,'Standard',false)&input=QURDU3tDaHQ1MTJfXzUwbl90aHRfM2xmZzR9UA&oeol=VT)

---

## `SCD{d3comp1lat1on_15nt_h4rd}`


<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
