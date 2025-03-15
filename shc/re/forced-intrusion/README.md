# forced-intrusion

[library.m0unt41n.ch/challenges/forced-intrusion](https://library.m0unt41n.ch/challenges/forced-intrusion) ![](../../resources/re.svg) ![](../../resources/easy.svg) 

# TL;DR

Ugh. We get a binary, which seems to be doing... stuff.

```
$ ./main 
Please enter the arguments: asdf
Invalid option s
```

# Decompilation

The program is quite long - full decompiled and somewhat simplified source:
[main.c](https://github.com/mufl0n/mufl0n.github.io/blob/main/shc/re/forced-intrusion/main.c). Don't expect it to work &#128578;, the decompile is optimized
for readability and understanding of the code. The overall logic seems to be:

*   A `string` is initialized with `duckslovelettuce`
*   We can enter a string of characters. The characters are "opcodes" (`a`...`j`),
    `a` and `b` accept an integer argument.
*   We can use a single character only once
*   Each of the opcodes triggers a certain operation on `string1`
*   At the end of input, `string` is expected to contain a flag.
*   There is a whole bunch of `usleep()` spread across the code, to make it
    run slower.
*   There is a whole bunch of manually coded Base64 routines. They better be right...

## Opcodes

What are the opcodes? They are all mapped to C functions, doing certain
operation. Function names are mine &#128578;

| Code | Provisional function name  | Useful? | Why?                                                               |
| ---- | -------------------------- | ------- | ------------------------------------------------------------------ |
| `a`  | `fetchIntAndAddToVal()`    | NO      | modifies 'val', which is used only in 'b'                          |
| `b`  | `parseIntIntoTempString()` | NO      | no side effects, only updates its own local buffer                 |
| `c`  | `xorStringWith0x2A()`      | YES     | potentially useful                                                 |
| `d`  | `cycleRngManyTimes()`      | WEAK    | takes lots of time, only fiddles with RNG seed                     |
| `e`  | `stringToBase64()`         | MAYBE   | that would need a lot to bring it to "shc"? less likely, but maybe |
| `f`  | `base64ToString()`         | MAYBE   | but, that would need b64 to begin with. but could work.            |
| `g`  | `appendLiquidSnake()`      | NO      | sleep(313376969)                                                   |
| `h`  | `expandCharsFourWay()`     | MAYBE   | does some potentially useful stuff                                 |
| `i`  | `shuffleString()`          | YES     | very likely to be useful                                           |
| `j`  | `makeRandomString()`       | WEAK    | probably not, writes to buf1000 way after the flag                 |

## Key observations

*   `a`, `b` and `g` are just distractions, not affecting `string1`
*   `d` does not do anything apart from taking a lot of time and changing RNG seed.
    Which we won't be reusing after.
*   `j` impacts `string1`, but quite far, we probably don't care.

This leaves five opcodes, without arguments - and none of them in the "slow" category.
That's good enough for brute force.

# Getting the flag

```python
import itertools
import pwn

valid_opcodes = ['c', 'e', 'f', 'h', 'i']
all_inputs = []
for n in range(1,6):
    all_inputs.extend(list(itertools.permutations(valid_opcodes, n)))

for arg in all_inputs:
    arg = "".join(arg)
    io = pwn.process("./main")
    io.recvuntilS(b"Please enter the arguments: ")
    io.sendline(arg.encode('ascii'))
    s = io.recvall()
    io.close()
    print(arg," ",s)
```

After quite some wait and many unsuccessful attempts, we get:

```
[+] Starting local process './main': pid 187150
[+] Receiving all data: Done (385B)
[*] Process './main' stopped with exit code 0 (pid 187150)
cheif   b'I think you solved it: shc2023{k33p_th3_b3st-brut3_th3_r3st}\nAlso, you deserve to know the initial string, just for the memes: xxxxxxxxxxxxxxxx\nGreat now to the mission briefing. Infiltrate the enemy fortress, Outer Heaven, and destroy Metal Gear, the final weapon! Our spies have found a vulnerable door near the hangar, exploit it, enter the fortress and learn about the Metal Gear.\n'
```

Which is reproducible in the remote instance too:

```
$ ncat --ssl 6c165c53-8359-4063-97b7-7a7f3e240d71.library.m0unt41n.ch 1337
Please enter the arguments: cheif
I think you solved it: shc2023{k33p_th3_b3st-brut3_th3_r3st}
Also, you deserve to know the initial string, just for the memes: duckslovelettuce
Great now to the mission briefing. Infiltrate the enemy fortress, Outer Heaven, and destroy Metal Gear, the final weapon! Our spies have found a vulnerable door near the hangar, exploit it, enter the fortress and learn about the Metal Gear.
```

---

## `shc2023{k33p_th3_b3st-brut3_th3_r3st}`


<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
