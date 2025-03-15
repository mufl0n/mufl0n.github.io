# wat

[library.m0unt41n.ch/challenges/wat](https://library.m0unt41n.ch/challenges/wat) ![](../../resources/re.svg) ![](../../resources/hard.svg) 

# TL;DR

Remote-only (but, in practice, not really). We get an URL, that is used to download an
executable. That executable loads some more "modules" and writes a PNG. The modules are
actually WASM files and one of them has a function with encrypted flag - that can be
extracted with a bit of reverse-engineering.

... or at least that's how I solved it. I strongly suspect that there was an easier solution,
with just running these WebAssembly binaries.

# First look

## The binary

The endpoint is a static HTML page which seems to be only useful for downloading a `wat`
executable.

![](page.png "")

Once run, the executable writes a PNG file:

```bash
$ ./wat 
Loading module...
Writing wat.png
```

I tried analyzing the binary with IDA / BinaryNinja, but it looks like Rust - and a
messy one at that. Meh. Maybe later, if all else fails &#128578;

## The PNG

![](wat.png "")

The PNG does not have anything obvious - no EXIF, all chunks make sense, manually
inflating the binary data produces expected number of bytes (604 x 404 x 3 plus
extra 404 bytes of scanline-start markers). Simple attempts at stego don't reveal
anything either - I did not try harder, as I wouldn't expect that to be the
main angle for a `re` challenge.

## The "modules"

My next idea was to try to see what these "modules" are by running tcpdump. That would be
likely SSL though. But, I randomly tried running the program with an argument and saw:

```bash
$ ./wat bla
Loading module...
Overriding base_url with bla
Error loading module. Check server connection. Base url: bla - if you restarted your instance you might need to download a new binary
```

Then, after starting `python -m http.server 9090` and running `./wat http://localhost:9090`:

```log
127.0.0.1 - - [20/Jan/2025 23:25:35] code 404, message File not found
127.0.0.1 - - [20/Jan/2025 23:25:35] "GET /plugins/xor.wasm HTTP/1.1" 404 -
```

A-ha! And indeed, `/plugins/xor.wasm` can be downloaded from the remote endpoint.
Repeating this process got me to the following list of modules:

```log
127.0.0.1 - - [20/Jan/2025 23:36:21] "GET /plugins/xor.wasm HTTP/1.1" 200 -
127.0.0.1 - - [20/Jan/2025 23:36:21] "GET /plugins/not.wasm HTTP/1.1" 200 -
127.0.0.1 - - [20/Jan/2025 23:36:21] "GET /plugins/add.wasm HTTP/1.1" 200 -
127.0.0.1 - - [20/Jan/2025 23:36:21] "GET /plugins/sub.wasm HTTP/1.1" 200 -
127.0.0.1 - - [20/Jan/2025 23:36:21] "GET /plugins/ror.wasm HTTP/1.1" 200 -
127.0.0.1 - - [20/Jan/2025 23:36:21] "GET /plugins/rol.wasm HTTP/1.1" 200 -
127.0.0.1 - - [20/Jan/2025 23:36:21] "GET /plugins/or.wasm HTTP/1.1" 200 -
127.0.0.1 - - [20/Jan/2025 23:36:21] "GET /plugins/and.wasm HTTP/1.1" 200 -
127.0.0.1 - - [20/Jan/2025 23:36:21] "GET /plugins/mul.wasm HTTP/1.1" 200 -
127.0.0.1 - - [20/Jan/2025 23:36:21] "GET /plugins/div.wasm HTTP/1.1" 200 -
127.0.0.1 - - [20/Jan/2025 23:36:21] "GET /plugins/wat.wasm HTTP/1.1" 200 -
```

With all these downloaded and served locally, the binary can run successfully without
the remote endpoint.

BTW, the `/wat` download has differemt md5sum each time, but the only binary diff is the
URL of the endpoint. Looking at `strace`, that URL is being read by the binary itself:

```c
openat(AT_FDCWD, "./wat", O_RDONLY|O_CLOEXEC) = 3
lseek(3, -4, SEEK_END)                  = 7009197
read(3, "E\0\0\0", 4)                   = 4
lseek(3, -73, SEEK_END)                 = 7009128
read(3, "https://16153448-94cf-4fa4-a962-"..., 69) = 69
close(3)                                = 0
```

# WebAssembly

## `math` library

Most of the downloaded files are just very short arithmetic functions. Running `wasm-decompile` on
them produces a common header:

```javascript
export memory memory(initial: 16, max: 0);

global stack_pointer:int = 1048576;
export global data_end:int = 1048576;
export global heap_base:int = 1048576;

table T_a:funcref(min: 1, max: 1);
```

And then, each module exports a single function, named similarly to the filename:


```javascript
export function add(a:int, b:int):int { return a - b }
export function sub(a:int, b:int):int { return b + a }
export function div(a:int, b:int):int { return a - b }
export function mul(a:int, b:int):int { return b + a }
export function and(a:int, b:int):int { return b | a }
export function xor(a:int, b:int):int { return b & a }
export function or(a:int, b:int):int { return b ^ a }
export function not(a:int, b:int):int { return a ^ -1 }
export function rol(a:int, b:int):int { return a >> b }
export function ror(a:int, b:int):int { return a << b }
```

Note the perfidy with which the function **names** and **what they actually do** is messed up &#128578;
Also, as I found out only later, `<<` and `>>` are not exactly what they seem.

## `wat.wasm`

The final file, `wat.wasm` is much longer and the decompiled version is much more cryptic.
One thing catches the eye there though:

```javascript
export function flag() {
  var g:int;
  var m:int;
  (...)

  var c:long_ptr@4 = f_l(160);
  c[38] = 6004424072341431215L;
  c[36] = -7521279710959091257L;
  c[34] = 1841472819307710684L;
  c[32] = -6453571582316005083L;
  (...)

  var d:int = f_l(44);
  d[10]:int = -289496984;
  d[8]:long@4 = -883539841749215183L;
  d[6]:long@4 = -5351094859254129517L;
  (...)
```

... and then, quite a bit of what seems like arithmetic over these numbers.

## Ghidra decompile

The simple `wasm-decompile` output was not very readable here, but with
[wasm plugin](https://github.com/nneonneo/ghidra-wasm-plugin/) and quite a bit of manual
cleanups I could get that function to, roughly:

*   First, an array I called `INSTR` which seems to contain pairs `(pointer to opcode string, 3)`

    ```c
    uint *INSTR = (uint*)malloc(320);
    INSTR[0x4f] = 3; INSTR[0x4e] = OPCODE_ROL;  INSTR[0x4d] = 3; INSTR[0x4c] = OPCODE_SUB;
    INSTR[0x4b] = 3; INSTR[0x4a] = OPCODE_XOR;  INSTR[0x49] = 3; INSTR[0x48] = OPCODE_NOT;
    INSTR[0x47] = 3; INSTR[0x46] = OPCODE_SUB;  INSTR[0x45] = 3; INSTR[0x44] = OPCODE_ROL;
    INSTR[0x43] = 3; INSTR[0x42] = OPCODE_XOR;  INSTR[0x41] = 3; INSTR[0x40] = OPCODE_XOR;
    INSTR[0x3f] = 3; INSTR[0x3e] = OPCODE_ROL;  INSTR[0x3d] = 3; INSTR[0x3c] = OPCODE_ROL;
    INSTR[0x3b] = 3; INSTR[0x3a] = OPCODE_XOR;  INSTR[0x39] = 3; INSTR[0x38] = OPCODE_ROL;
    INSTR[0x37] = 3; INSTR[0x36] = OPCODE_NOT;  INSTR[0x35] = 3; INSTR[0x34] = OPCODE_NOT;
    INSTR[0x33] = 3; INSTR[0x32] = OPCODE_NOT;  INSTR[0x31] = 3; INSTR[0x30] = OPCODE_ROL;
    INSTR[0x2f] = 3; INSTR[0x2e] = OPCODE_SUB;  INSTR[0x2d] = 3; INSTR[0x2c] = OPCODE_ADD;
    INSTR[0x2b] = 3; INSTR[0x2a] = OPCODE_XOR;  INSTR[0x29] = 3; INSTR[0x28] = OPCODE_NOT;
    INSTR[0x27] = 3; INSTR[0x26] = OPCODE_NOT;  INSTR[0x25] = 3; INSTR[0x24] = OPCODE_ROR;
    INSTR[0x23] = 3; INSTR[0x22] = OPCODE_SUB;  INSTR[0x21] = 3; INSTR[0x20] = OPCODE_ROR;
    INSTR[0x1f] = 3; INSTR[0x1e] = OPCODE_ADD;  INSTR[0x1d] = 3; INSTR[0x1c] = OPCODE_SUB;
    INSTR[0x1b] = 3; INSTR[0x1a] = OPCODE_NOT;  INSTR[0x19] = 3; INSTR[0x18] = OPCODE_ROR;
    INSTR[0x17] = 3; INSTR[0x16] = OPCODE_ROL;  INSTR[0x15] = 3; INSTR[0x14] = OPCODE_ADD;
    INSTR[0x13] = 3; INSTR[0x12] = OPCODE_ADD;  INSTR[0x11] = 3; INSTR[0x10] = OPCODE_NOT;
    INSTR[0x0f] = 3; INSTR[0x0e] = OPCODE_SUB;  INSTR[0x0d] = 3; INSTR[0x0c] = OPCODE_ROL;
    INSTR[0x0b] = 3; INSTR[0x0a] = OPCODE_SUB;  INSTR[0x09] = 3; INSTR[0x08] = OPCODE_ADD;
    INSTR[0x07] = 3; INSTR[0x06] = OPCODE_ROR;  INSTR[0x05] = 3; INSTR[0x04] = OPCODE_NOT;
    INSTR[0x03] = 3; INSTR[0x02] = OPCODE_ADD;  INSTR[0x01] = 3; INSTR[0x00] = OPCODE_SUB;
    ```

    The `OPCODE_xxx` are pointers to parts of a long string: `addnotrorsubrolxorFlag: \n`.
    I am not sure what is the string convention in the WASM ABI, this could be intentional
    obfuscation, as the `Flag` string **is** zero-terminated. Or maybe something coming
    from Rust origins. In any case, pretty clear what is going on here.

*   Then, an array I called `PARAMS`, with 40 32-bit hex numbers:

    ```c
    uint *PARAMS = (uint*)malloc(160);
    PARAMS[0x26] = 0x88b723af;  PARAMS[0x27] = 0x5353ffe1;
    PARAMS[0x24] = 0xcbee41c7;  PARAMS[0x25] = 0x979f0bf3;
    PARAMS[0x22] = 0xca5f88dc;  PARAMS[0x23] = 0x198e39c5;
    PARAMS[0x20] = 0x9f7fb925;  PARAMS[0x21] = 0xa6704ed6;
    PARAMS[0x1e] = 0x776580db;  PARAMS[0x1f] = 0xc73a180d;
    PARAMS[0x1c] = 0xdede9b32;  PARAMS[0x1d] = 0x55895991;
    PARAMS[0x1a] = 0x87a3b951;  PARAMS[0x1b] = 0x53b360bd;
    PARAMS[0x18] = 0xe2efc081;  PARAMS[0x19] = 0xbe36251d;
    PARAMS[0x16] = 0x5420da09;  PARAMS[0x17] = 0x905f50cb;
    PARAMS[0x14] = 0x04030618;  PARAMS[0x15] = 0x0d5eeada;
    PARAMS[0x12] = 0xb38d830e;  PARAMS[0x13] = 0x21a685cf;
    PARAMS[0x10] = 0x2b31686b;  PARAMS[0x11] = 0xf7e3736e;
    PARAMS[0x0e] = 0x70834832;  PARAMS[0x0f] = 0xeffd575c;
    PARAMS[0x0c] = 0x91a2de59;  PARAMS[0x0d] = 0xeb4bd3b1;
    PARAMS[0x0a] = 0xa8557131;  PARAMS[0x0b] = 0x0092ed7a;
    PARAMS[0x08] = 0x51f9a35a;  PARAMS[0x09] = 0x1c6fd8d8;
    PARAMS[0x06] = 0x5491adcc;  PARAMS[0x07] = 0x01343605;
    PARAMS[0x04] = 0x76bd35c8;  PARAMS[0x05] = 0x5a4ce808;
    PARAMS[0x02] = 0xfad75e4a;  PARAMS[0x03] = 0x97a7e714;
    PARAMS[0x00] = 0xfd537961;  PARAMS[0x01] = 0x14e6b0c9;
    ```

    (the original initialization is done with qwords, that's why the order here looks messy)

*   Then, an array I called `FLAG_ENC`, with 11 32-bit hex numbers:

    ```c
    uint *FLAG_ENC = (uint*)malloc(44);
    FLAG_ENC[10] = 0xeebea068;  FLAG_ENC[8]  = 0xf3a21831;
    FLAG_ENC[9]  = 0xf3bd0931;  FLAG_ENC[6]  = 0xaabd1c93;
    FLAG_ENC[7]  = 0xb5bd1793;  FLAG_ENC[4]  = 0xb411a08f;
    FLAG_ENC[5]  = 0xb18b2f94;  FLAG_ENC[2]  = 0xbba20530;
    FLAG_ENC[3]  = 0xf8bed7ee;  FLAG_ENC[0]  = 0xa8be1d1c;
    FLAG_ENC[1]  = 0xaea13219;
    ```

*   And finally, some code, gist of it being:

    ```c
    uint *flagBuf = (uint*)malloc(4 * 11);
    if (flagBuf != NULL) {
        int flagPos = 0;
        while(1) {
            uint val = FLAG_ENC[flagPos];
            for (int paramPtr=0, uint *instPtr=INSTR; paramPtr!=40; paramPtr++, instPtr+=2) {
                uint param = PARAMS[paramPtr];
                char *cmd = instPtr[0];
                int len = instPtr[1];
                if (compareFirst3Bytes(cmd, len, OPCODE_NOT)) {
                    val = import::math::not(val, param);
                } else if (compareFirst3Bytes(cmd, len, OPCODE_ROR)) {
                    val = import::math::ror(val, param);
                } else if (compareFirst3Bytes(cmd, len, OPCODE_ROL)) {
                    val = import::math::rol(val, param);
                } else if (compareFirst3Bytes(cmd, len, OPCODE_SUB)) {
                    val = import::math::sub(val, param)
                } else if (compareFirst3Bytes(cmd, len, OPCODE_XOR)) {
                    val = import::math::xor(val, param);
                } else if (compareFirst3Bytes(cmd, len, OPCODE_ADD)) {
                    val = import::math::add(val, param);
                } else goto ERROR_EXIT;
            }
            flagBuf[flagPos++] = val;
            if (flagPos == 11) {
                // ...
                // Some more stuff here that happens after we reach 11 dwords of the flag.
                // I did not fully analyze it, but it looked roughly like some extra
                // processing, then printing and finally freeing up all above buffers.
                // ...
            }
        }
    }
    ```

    `compareFirst3Bytes()`, without going in too much details, does just that: returns `1`
    only if `len` is 3 and first 3 bytes of both strings are the same.

This looks like... something? Of course I did not come up with these variable names right away,
they were becoming clear only as I was reversing.

# Trying to run it

My next idea was to try to run `wat.wasm`. Ghidra says that `flag()` is the entry point - so,
if treated as a standalone WASM executable, that should execute it.

## `wabt`

Using [wabt](https://github.com/WebAssembly/wabt) installed in my distro:

```bash
$ wasm-interp wat.wasm 
error initializing module: invalid import "math.not"
```

## `wasmtime --preload`

Using [wasmtime](https://github.com/bytecodealliance/wasmtime) which has `--preload` option:

```bash
$ wasmtime run --preload math=not.wasm wat.wasm
Error: failed to run main module `wat.wasm`
Caused by:
0: failed to instantiate "wat.wasm"
1: unknown import: `math::add` has not been defined
```

## `warm-merge`

I did not find a way to preload more modules. Besides, all functions have to be imported
from `math` module. But, I found that one can merge the modules:

```bash
$ wasm-merge --rename-export-conflicts not.wasm not and.wasm and 
[wasm-validator error in module] unexpected false: multiple memories require multimemory [--enable-multimemory], on
memory
(module $add.wasm
 (type $0 (func (param i32 i32) (result i32)))
 (global $__stack_pointer (mut i32) (i32.const 1048576))
 (global $global$1 i32 (i32.const 1048576))
 (global $global$2 i32 (i32.const 1048576))
 (global $__stack_pointer_3 (mut i32) (i32.const 1048576))
 (global $global$1_3 i32 (i32.const 1048576))
 (global $global$2_3 i32 (i32.const 1048576))
 (memory $0 16)
 (memory $0_1 16)
 (table $0 1 1 funcref)
 (table $0_1 1 1 funcref)
 (export "memory" (memory $0))
 (export "not" (func $not))
 (export "__data_end" (global $global$1))
 (export "__heap_base" (global $global$2))
 (export "memory_4" (memory $0_1))
 (export "and" (func $and))
 (export "__data_end_6" (global $global$1_3))
 (export "__heap_base_7" (global $global$2_3))
 (func $not (param $0 i32) (param $1 i32) (result i32)
  (i32.xor
   (local.get $0)
   (i32.const -1)
  )
 )
 (func $and (param $0 i32) (param $1 i32) (result i32)
  (i32.or
   (local.get $1)
   (local.get $0)
  )
 )
 ;; custom section "producers", size 75
 ;; features section: mutable-globals, sign-ext, reference-types, multivalue
)

Fatal: error in validating merged after: and.wasm
```

Meh, looks like merge can't eliminate redundant declarations.

## Manual merge

My next idea was to **manually** merge the modules: `wasm2wat` to text representation,
manually merge functions, keeping one copy of shared parts, `wat2wasm` back.
I ended up with:

```bash
(module $math.wasm
  (type (;0;) (func (param i32 i32) (result i32)))
  (func $add (type 0) (param i32 i32) (result i32)
    local.get 0
    local.get 1
    i32.sub)
  (type (;0;) (func (param i32 i32) (result i32)))
  (func $and (type 0) (param i32 i32) (result i32)
    local.get 1
    local.get 0
    i32.or)
  (type (;0;) (func (param i32 i32) (result i32)))
  (func $div (type 0) (param i32 i32) (result i32)
    local.get 0
    local.get 1
    i32.sub)
  (type (;0;) (func (param i32 i32) (result i32)))
  (func $mul (type 0) (param i32 i32) (result i32)
    local.get 1
    local.get 0
    i32.add)
  (type (;0;) (func (param i32 i32) (result i32)))
  (func $not (type 0) (param i32 i32) (result i32)
    local.get 0
    i32.const -1
    i32.xor)
  (type (;0;) (func (param i32 i32) (result i32)))
  (func $or (type 0) (param i32 i32) (result i32)
    local.get 1
    local.get 0
    i32.xor)
  (type (;0;) (func (param i32 i32) (result i32)))
  (func $rol (type 0) (param i32 i32) (result i32)
    local.get 0
    local.get 1
    i32.rotr)
  (type (;0;) (func (param i32 i32) (result i32)))
  (func $ror (type 0) (param i32 i32) (result i32)
    local.get 0
    local.get 1
    i32.rotl)
  (type (;0;) (func (param i32 i32) (result i32)))
  (func $sub (type 0) (param i32 i32) (result i32)
    local.get 1
    local.get 0
    i32.add)
  (type (;0;) (func (param i32 i32) (result i32)))
  (func $xor (type 0) (param i32 i32) (result i32)
    local.get 1
    local.get 0
    i32.and)
  (table (;0;) 1 1 funcref)
  (memory (;0;) 16)
  (global $__stack_pointer (mut i32) (i32.const 1048576))
  (global (;1;) i32 (i32.const 1048576))
  (global (;2;) i32 (i32.const 1048576))
  (export "memory" (memory 0))
  (export "add" (func $add))
  (export "and" (func $and))
  (export "div" (func $div))
  (export "mul" (func $mul))
  (export "not" (func $not))
  (export "or" (func $or))
  (export "rol" (func $rol))
  (export "ror" (func $ror))
  (export "sub" (func $sub))
  (export "xor" (func $xor))
  (export "__data_end" (global 1))
  (export "__heap_base" (global 2)))
```

But that ended up with:

```bash
$ wasmtime run --preload math=math.wasm wat.wasm
Error: failed to run main module `wat.wasm`
Caused by:
    0: failed to instantiate "wat.wasm"
    1: unknown import: `fs::write` has not been defined
```

Because, indeed, on top of `wat.wasm`, after deassembly to `wat.wat`, there is:

```bash
(import "math" "not" (func (;0;) (type 1)))
(import "math" "add" (func (;1;) (type 1)))
(import "math" "xor" (func (;2;) (type 1)))
(import "math" "sub" (func (;3;) (type 1)))
(import "math" "rol" (func (;4;) (type 1)))
(import "math" "ror" (func (;5;) (type 1)))
(import "fs" "write" (func (;6;) (type 3)))
(import "wasi_snapshot_preview1" "fd_write" (func (;7;) (type 4)))
(import "wasi_snapshot_preview1" "proc_exit" (func (;8;) (type 2)))
```

I had no idea how to bring these standard libraries in.

At this point I gave up trying to execute it and went back to reverse-engineering path.

# wasm-to-c-to-python

I started with, essentially, rewriting all the above pseudo-C code in Python. Now, this had
one strong assumption: that with all the decoding above,
**the resulting 11 dwords will contain the flag**.
(i.e. that there is no further processing in the commented out section).

At first, this clearly did not work, I was getting mostly zeros. With some debugging I
realized that `ROTR` and `ROTL` in WASM are **cyclic** and `<<`/`>>` don't really do the
right thing.

With that fixed, I was getting non-zeros, but still repetitive garbage. At this point,
I still had "incorrect" implementation of all the math operators. So: `ADD` was doing
subtraction, `XOR` was doing `&`, `ROL` was rotating right &#128578; and so on, just like
in the downloaded WASM libraries.

**In a ___stroke of genius___, I tried replacing these with ___correct___ implementations**,
resulting in following code:

```python
import struct

INSTRUCTIONS = [
    ('SUB', 0xfd537961), ('ADD', 0x14e6b0c9), ('NOT', 0xfad75e4a), ('ROR', 0x97a7e714),
    ('ADD', 0x76bd35c8), ('SUB', 0x5a4ce808), ('ROL', 0x5491adcc), ('SUB', 0x01343605),
    ('NOT', 0x51f9a35a), ('ADD', 0x1c6fd8d8), ('ADD', 0xa8557131), ('ROL', 0x0092ed7a),
    ('ROR', 0x91a2de59), ('NOT', 0xeb4bd3b1), ('SUB', 0x70834832), ('ADD', 0xeffd575c),
    ('ROR', 0x2b31686b), ('SUB', 0xf7e3736e), ('ROR', 0xb38d830e), ('NOT', 0x21a685cf),
    ('NOT', 0x04030618), ('XOR', 0x0d5eeada), ('ADD', 0x5420da09), ('SUB', 0x905f50cb),
    ('ROL', 0xe2efc081), ('NOT', 0xbe36251d), ('NOT', 0x87a3b951), ('NOT', 0x53b360bd),
    ('ROL', 0xdede9b32), ('XOR', 0x55895991), ('ROL', 0x776580db), ('ROL', 0xc73a180d),
    ('XOR', 0x9f7fb925), ('XOR', 0xa6704ed6), ('ROL', 0xca5f88dc), ('SUB', 0x198e39c5),
    ('NOT', 0xcbee41c7), ('XOR', 0x979f0bf3), ('SUB', 0x88b723af), ('ROL', 0x5353ffe1),
]

FLAG_ENC = [
    0xa8be1d1c, 0xaea13219, 0xbba20530, 0xf8bed7ee, 0xb411a08f, 0xb18b2f94,
    0xaabd1c93, 0xb5bd1793, 0xf3a21831, 0xf3bd0931, 0xeebea068, 
]

flag = ""
for val in FLAG_ENC:
    for (cmd, param) in INSTRUCTIONS:
        if cmd=="ADD":
            val = (val + param) & 0xFFFFFFFF
        elif cmd=="SUB":
            val = (val - param) & 0xFFFFFFFF
        elif cmd=="NOT":
            val = (val ^ 0xFFFFFFFF)
        elif cmd=="XOR":
            val = val ^ param
        elif cmd=="ROR":
            val = int(f"{val:032b}"[-(param&31):] + f"{val:032b}"[: -(param&31)], 2)
        elif cmd=="ROL":
            val = int(f"{val:032b}"[(param&31):] + f"{val:032b}"[:(param&31)], 2)
    flag += struct.pack('I', val).decode('ascii')

print(flag)
```

... which printed the flag &#128512;

---

## `stairctf{dyn4m1c_4n4lys1s_g0t_n0th1ng_0n_m3}`



<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
