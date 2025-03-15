# knive

[library.m0unt41n.ch/challenges/knive](https://library.m0unt41n.ch/challenges/knive) ![](../../resources/re.svg) ![](../../resources/medium.svg) 

# TL;DR

The program asks for a password, and bails out.

# Decompilation

Note that most of the error checking has been removed for readability.

```c
int main(int argc, char **argv, char **envp) {
  int pid_status;
  z_stream zstream;
  int pipe_fd[2];
  char password[128];
  char buf[1032];

  // Create volatile file "knive" in RAM
  int fd = memfd_create("knive", 0);

  // Initialize zlib
  memset(&zstream, 0, sizeof(zstream));
  inflateInit_(&zstream, "1.2.11", sizeof(zstream));

  // Initialize zlib's z_stream structure
  zstream.avail_in = int07AAh;
  zstream.next_in = &str128_1_minus_1;

  // Keep on decompressing and write results to "knive"
  do {
    zstream.avail_out = 1024;
    zstream.next_out = buf;
    int res = inflate();
    int inflatedLen = 1024-zstream.avail_out;
    write(fd, buf, 1024-zstream.avail_out) != inflatedLen);
  } while (!zstream.avail_out || res != Z_STREAM_END);

  // Create pipe for IPC
  pipe(pipe_fd);

  // Fork
  int pid = fork();
  if (pid) {
    // Parent process will write three 128-byte buffers to the pipe:
    // - str128_1
    // - str128_2
    // - password
    close(pipe_fd[0]);
    write(pipe_fd[1], &str128_1, 128);
    write(pipe_fd[1], &str128_2, 128);
    puts("Please enter the password:");
    memset(&password, 0, sizeof(password))
    fgets(password, 128, stdin);
    write(pipe_fd[1], password, 128);
    waitpid(pid, &pid_status, 0);
    if (pid_status==42) puts("Congratulations, this input is correct!");
                   else puts("Sorry, this is not correct :(");
  } else {
    // But at this point we don't know what the child process will do
    // (and when it will return 42).
    close(pipe_fd[1]);
    **argv = LOBYTE(pipe_fd[0]) + 48;
    (*argv)[1] = 0;
    fexecve(fd, argv, environ) == -1);
  }
  return 0;
}
```

# Embedded binary

First, let's catch that embedded binary which is extracted into `/memfd:knive` - and keep it simple:

*    Run the program under a debugger
*    Set breakpoint just before `fork()`
*    Once program gets there, pull the binary out of `/proc/`:

```
$ ls -la /proc/$(pgrep knive)/fd
(...)
lrwx------. 1 muflon muflon 64 Aug 26 01:10 3 -> '/memfd:knive (deleted)'

$ cp /proc/$(pgrep knive)/fd/3 knive2
$ file knive2
knive2: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=67f3930dfa511a4d0217da4f06808d97a7e57e06, for GNU/Linux 3.2.0, stripped
```

# Decompile

Now, let's decompile that:

```c
int main(char argc, char **argv, char **envp) {
  char buf1[128], buf2[128], buf3[128];

  int fd = **argv - 48;
  read(fd, buf1, 128);
  read(fd, buf2, 128);
  read(fd, buf3, 128);
  int matchingBytes = 0;
  for (int i=0; i<128; i++)
    if (buf1[i]==((buf3[i]^buf2[i])^0x2A))
      matchingBytes++;
  if (matchingBytes==128) return 42;
                     else return 0;
}
```

# Analysis

So, together with the "sending" part above, what will happen here is that the child process will read three 128-byte buffers:

*   `str128_1` (from original binary)
*   `str128_2` (from original binary)
*   `password` (from user input)

And return the successful exit code (42) only if for all bytes, `str128_1 = password ^ str128_2 ^ 0x2A` is true.
XOR is fully commutative, so we can recover the password simply by XORing the other 3 things.

## Getting secret strings

Let's extract `str128_1` and `str128_2` from the original binary:

```python
str128_1 = bytes.fromhex("9CED5B6D6C1445189EBD5EAFC747B95341B1A05C08201FE9D22BA5A99A0AB614"
                         "160358B04D3401AFDBDEB677F17AD7DCED41310A476AD1A69C418D62624CD498"
                         "A88989FD21A4516B4E31A09810F86182FE422349895F2728A91F749DD97DDFEB"
                         "EE70678D51FF384F72FBECFBCEFBCCCCCECCCEF5BAEFEE6FD9B2D12549045146")
str128_2 = bytes.fromhex("C5AF1275760C5C49E0FF47DADD1DE34918AAFE457D3A539C936FBEF5837FF50B"
                         "634F42E80C414FBD9097AE6DE936CE94F65B7A5D6740FB8CB66BA7484866FEB2"
                         "82A3A3D70B8E7B41641B8AB23AD24BA8D4680963A3750D0283355EB7F357F5C1"
                         "C45A4DA77BD5126558D1C6D1E4D1E6E6E4E6E4DF90C5C445F398FB0F632E7B6C")
```

## Getting the pasword

```python
print(bytes([str128_1[i]^str128_2[i]^0x2A for i in range(128)]))

b'shc2023{Th3_0pp0s1t3_0f_kn1v3_i5_f0rk_d8ac202f3b10a}\n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
```

---

## `shc2023{Th3_0pp0s1t3_0f_kn1v3_i5_f0rk_d8ac202f3b10a}`




<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
