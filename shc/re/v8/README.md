# v8

[library.m0unt41n.ch/challenges/v8](https://library.m0unt41n.ch/challenges/v8) ![](../../resources/re.svg) ![](../../resources/medium.svg) 

# TL;DR

This is fully remote challenge - we get a fancy Web UI, with a `Submit` button.

# Initial look

Let's just press the button:

```
SecurePrinter Configuration Interface 2.1.3b 🖨️
Enter your config:
Made by Kiwi 🐶

Configuration Output

     ____
    / _  |   Frida 16.3.1 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
   . . . .
   . . . .   Connected to Local System (id=local)
Spawning `./secureprint-abi.bin`...
Spawned `./secureprint-abi.bin`. Resuming main thread!
[Local::secureprint-abi.bin ]-> Enter the secret password: Sorry, that's not the correct password. Try again.
Process terminated

Thank you for using Frida!
```

And now, with `test` as input:

```
ReferenceError: 'test' is not defined
    at  (/usr/src/app/userinput.js:1)
```

So, looks like a [Frida](http://frida.re) instance, controlled with Javascript
inputs. Looks like we will be typing Javascript, that controls some application.
Some relevant docs: [JS API](https://frida.re/docs/javascript-api) and
[JS examples](https://frida.re/docs/examples/javascript)

# Some initial poking with Frida:

```js
console.log(Process.platform);
console.log(Process.arch);
console.log(Process.mainModule.path);
```
Leads to:
```
linux
x64
/usr/src/app/secureprint-abi.bin
```

# Extracting the binary

Can we get that file?

```js
console.log(File.readAllBytes("/usr/src/app/secureprint-abi.bin"));`
```
```
           0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
00000000  7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00  .ELF............
00000010  03 00 3e 00 01 00 00 00 00 12 00 00 00 00 00 00  ..>.............
00000020  40 00 00 00 00 00 00 00 08 40 00 00 00 00 00 00  @........@......
(...)
000047a0  e9 3e 00 00 00 00 00 00 1a 01 00 00 00 00 00 00  .>..............
000047b0  00 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00  ................
000047c0  00 00 00 00 00 00 00 00                          ........
Spawned `./secureprint-abi.bin`. Resuming main thread!
[Local::secureprint-abi.bin ]-> Enter the secret password: Sorry, that's not the correct password. Try again.
Process terminated

Thank you for using Frida!
```

Great! Let's save that hex dump to a `app.hex` and get it to work:
```
$ xxd -r <app.hex >app.bin
$ chmod a+x app.bin
$ ./app.bin
Enter the secret password: bla
Sorry, that's not the correct password. Try again.
```

# Reverse-engineering the binary

With a bit of polishing in IDA:
```c
#include <curl/curl.h>
#include <stdio.h>
#include <string.h>

size_t write_callback(char *ptr, size_t size, size_t nmemb, uint8_t *curl_result) {
    *(curl_result + size*nmemb) = 0;
    puts(ptr);
    return nmemb * size;
}

int main(void) {
    char encrypted[32];
    char password[112];
    char curl_result[1024];
    char url[1032];

    memcpy(encrypted, "zbh>=<;kz! dJbea(t|Cm*s]", 24);
    // This is really:
    // char encrypted[] = {
    //    0x7a, 0x62, 0x68, 0x3e, 0x3d, 0x3c, 0x3b, 0x6b,
    //    0x7a, 0x21, 0x20, 0x64, 0x4a, 0x62, 0x65, 0x61,
    //    0x28, 0x74, 0x7c, 0x43, 0x6d, 0x2a, 0x73, 0x5d
    // }
    printf("Enter the secret password: ");
    scanf("%99s", password);   // password is: 'shc2024{k33p_try1ng_p4l}'  (len=24)

    int len=strlen(password);
    char key=9;
    for (int i=0; i<len; i++, key++)
        password[i] = password[i] ^ key;
    password[len] = '\0';

    if (!strncmp(password, encrypted, 24)) {
        puts("Congratulations! You\'ve passed the challenge.");
        CURL *curl = curl_easy_init();
        if (curl) {
            // urlencoded: zbh%3E%3D%3C%3Bkz%21%20dJbea%28t%7CCm%2As%5D
            char *password_escaped = curl_easy_escape(curl, password, 0);
            snprintf(url, 1024, "http://localhost:1337/?password=%s", password_escaped);
            // https://curl.se/libcurl/c/CURLOPT_URL.html
            curl_easy_setopt(curl,CURLOPT_URL, url);
            // https://curl.se/libcurl/c/CURLOPT_WRITEFUNCTION.html
            curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION, write_callback);
            // https://curl.se/libcurl/c/CURLOPT_WRITEDATA.html
            curl_easy_setopt(curl,CURLOPT_WRITEDATA, curl_result);
            // https://curl.se/libcurl/c/curl_easy_perform.html
            int err = curl_easy_perform(curl);
            if (err) {
                char *err_str = curl_easy_strerror()
                fprintf(stderr, "curl_easy_perform() failed: %s\n", err_str);
            }
            curl_easy_cleanup(curl);
        }
    } else puts("Sorry, that\'s not the correct password. Try again.");
    return 0;
}
```
What it does:

*   Takes input from the user
*   Runs a trivial XOR over it, using key = `[9, 10, 11, ...]`
*   Compares with encrypted string: `"zbh>=<;kz! dJbea(t|Cm*s]"`
*   If there is a match, uses libcurl to fetch
    `http://localhost:1337/?password=<password>`
*   The provided `write_callback()` function will print the result to screen.

# Running it locally

Let's get the password first.
[CyberChef](https://gchq.github.io/CyberChef/#recipe=XOR(%7B'option':'Hex','string':'090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20'%7D,'Standard',false)&input=emJoPj08O2t6ISBkSmJlYSh0fENtKnNd),
says: `shc2024{k33p_try1ng_p4l}`. That's obviously not the solution,
but should enable us to start the application. It works locally:

```
$ ./app.bin
Enter the secret password: shc2024{k33p_try1ng_p4l}
Congratulations! You've passed the challenge.
curl_easy_perform() failed: Couldn't connect to server
```

... but we need to find a way to pass this input to remote instance.

# Running it remotely

I could not find a way to send a string to standard input of the binary under
Frida. But, with more poking through above JS API documentation, I found
`Interceptor` example and `Memory.writeByteArray`. Which leads to a simple plan:

*   Attach it to `scanf()` (note: we have to use the exact libc import, so:
`__isoc99_scanf`)
*   During `onEnter`, save the pointer to the buffer.
*   Then, `onLeave`, put the plain text password in the buffer, zero-terminated:

```js
Interceptor.attach(Module.getExportByName('libc.so.6', '__isoc99_scanf'), {
  onEnter(args) {
    this.buf = args[1];
  },
  onLeave(result) {
    let password = [
        0x73, 0x68, 0x63, 0x32, 0x30, 0x32, 0x34, 0x7b,
        0x6b, 0x33, 0x33, 0x70, 0x5f, 0x74, 0x72, 0x79,
        0x31, 0x6e, 0x67, 0x5f, 0x70, 0x34, 0x6c, 0x7d,
        0x00
    ];
    Memory.writeByteArray(this.buf, password);
  }
})
```

And it works!
```
Spawned `./secureprint-abi.bin`. Resuming main thread!
[Local::secureprint-abi.bin ]-> Enter the secret password: Congratulations! You've passed the challenge.
shc2024{PRINTERZ_ARE_SUCH_A_HECKIN_PAIN}
Process terminated
```

---

## `shc2024{PRINTERZ_ARE_SUCH_A_HECKIN_PAIN}`


<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
