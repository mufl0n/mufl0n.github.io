# printer-manual

[library.m0unt41n.ch/challenges/printer-manual](https://library.m0unt41n.ch/challenges/printer-manual) ![](../../resources/re.svg) ![](../../resources/baby.svg) 

# TL;DR

We get a simple executable file, that asks a series of Y/N questions. After decompiling, we see that
the code is trivial and each answer contributes to establishing a number - and only one final value
of that number yields us the flag.

# The code

Here's slightly annotated IDA decompilation of the `printer-manual` binary:

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char *v3; // rax

  puts("Printer User Manual: Model XYZ-1000");
  puts("===================================");
  puts("Congratulations on your purchase of the XYZ-1000 printer!");
  puts("We're excited to introduce you to the world of printing...or at least attempt to.");
  puts("Please keep in mind that while we've tried our best to make this manual as informative as possible,");
  puts("we cannot guarantee that the printer will actually work when you need it to.\n");
  puts("Section 1: Getting Started");
  puts("-----------------------------------");
  puts("Question 1: Have you plugged in the printer?");
  if ( did_type_yes() )
  {
    response_count *= 2;
    puts("Proceed to Question 2.");
  }
  else
  {
    response_count *= 3;
    puts("Kindly reconsider your decision to own a printer. Also, please plug it in.");
  }
  puts("Question 2: Is the printer turned on?");
  if ( did_type_yes() )
  {
    puts("Congratulations! You've mastered step one of the printing process.");
    response_count *= 5;
  }
  else
  {
    puts("Please locate the power button and press it.");
    puts("If you cannot find the power button, we apologize for the bad design.");
    puts("It's probably hidden somewhere inconvenient.\n");
    response_count *= 7;
  }
  puts("Section 2: Ink Cartridge Installation");
  puts("-----------------------------------");
  puts("Question 1: Do you have ink cartridges?");
  if ( did_type_yes() )
  {
    puts("Proceed to Question 2.");
    response_count *= 11;
  }
  else
  {
    puts("Please ponder the meaning of life while contemplating the cost of ink cartridges.");
    response_count *= 13;
  }
  puts("Question 2: Are the ink cartridges compatible with this printer model?");
  if ( did_type_yes() )
  {
    puts("Congratulations again! You're on a roll.");
    response_count *= 17;
  }
  else
  {
    puts("Don't worry, we're used to disappointment.");
    puts("Please refer to the list of compatible cartridges in the appendix.\n");
    response_count *= 19;
  }
  puts("Section 3: Troubleshooting");
  puts("-----------------------------------");
  puts("Question 1: Is the printer refusing to work despite following all instructions?");
  if ( did_type_yes() )
  {
    puts("Welcome to the club. It's not you; it's the printer.");
    response_count *= 23;
  }
  else
  {
    puts("We don't believe you. Please double-check.");
    response_count *= 29;
  }
  puts("Question 2: Have you tried turning it off and on again?");
  if ( did_type_yes() )
  {
    puts("Did it work?");
    puts("    If yes, you're a wizard. Please teach us your ways.");
    puts("    If no, join the club again. We'll commiserate together.");
    response_count *= 31;
  }
  else
  {
    puts("Please try it. It's the universal solution to all printer-related issues.\n");
    response_count *= 37;
  }
  puts("Section 4: Final Thoughts");
  puts("-----------------------------------");
  puts("Congratulations, you've completed the Printer User Manual!");
  puts("We hope this manual has been somewhat helpful in navigating the treacherous waters of printer ownership.");
  puts("Remember, printers are like unreliable friends: they might not always be there when you need them,");
  puts("but they'll always manage to disappoint you when you least expect it.");
  puts("Happy printing... or not.\n");
  puts("Section 5: Hidden guide");
  puts("-----------------------------------");
  if ( response_count == 2227918 )
  {
    v3 = getenv("FLAG");
    printf("Something that nobody knows about printers: %s\n", v3);
  }
  else
  {
    puts("Not unlocked. Good luck on your own.");
  }
  return 0;
}
```

Separately the `response_count` is a global variable  intialized to `1`.

## Solution

Typing `2227918` into a random website coming up in Google search for `prime factorization online`
says that the right sequence is: `2 x 7 x 11 x 17 x 23 x 37 = 2227918`.

So, the sequence of responses is: `yes`, `no`, `yes`, `yes`, `yes`, `no`.

## The flag

With live instance started, that gets us the flag.

---

## `shc2024{XYZ-1000_i5_th3_b35t_pr1nt3r_0ut_th3r3!}`


<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
