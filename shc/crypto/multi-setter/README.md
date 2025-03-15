# multi-setter

[library.m0unt41n.ch/challenges/multi-setter](https://library.m0unt41n.ch/challenges/multi-setter) ![](../../resources/crypto.svg) ![](../../resources/easy.svg) 

# TL;DR

*Why not play with sets? I heard they are fun!*.

We get a Python program with interactive "value setting" - whatever that means.

# Code

```python
import time
import os

FLAG = os.getenv("FLAG","SHC24{THIS_IS_A_FAKE_FLAG}")
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_-/{}=()"
assert all(c in alphabet for c in FLAG)

class MyStorable:
    def __init__(self, value):
        self.value = value

class MyChar(MyStorable):
    def __init__(self, s):
        super().__init__(s)

    def __hash__(self):
        return (ord(self.value) * 127) % 500

class MyNumber(MyStorable):
    def __init__(self, value: int):
        super().__init__(value)

    def __hash__(self):
        return (self.value * 1337) % 500

def init_chal():
    sets = []
    for i in range(0, len(FLAG)):
        s: set[MyStorable] = set()
        for _ in range(5_000):
            # sets should store the value only once right ?
            s.add(MyChar(FLAG[i]))
        sets.append(s)
    return sets
print("Welcome to the challenge")
print("""___  ___      _ _   _        _____      _   _            _ 
|  \/  |     | | | (_)      /  ___|    | | | |          | |
| .  . |_   _| | |_ _ ______\ `--.  ___| |_| |_ ___ _ __| |
| |\/| | | | | | __| |______|`--. \/ _ \ __| __/ _ \ '__| |
| |  | | |_| | | |_| |      /\__/ /  __/ |_| ||  __/ |  |_|
\_|  |_/\__,_|_|\__|_|      \____/ \___|\__|\__\___|_|  (_)
                                                           """)
print("loading")
sets = init_chal()
print("loaded")

def add_batch(number_to_store:int,batch_size:int, set_number:int):
    for i in range(batch_size):
        m = MyNumber(number_to_store)
        sets[set_number].add(m)

batch_size = int(input("Enter the batch size :\n"))
while True:
    set_number = int(input("Enter the set number :\n"))
    number_to_store = int(input("Enter the number to store :\n"))
    add_batch(number_to_store,batch_size, set_number)
    print("Done")
    print("Do you want to continue ?")
    if input() == "n":
        break
```

# Analysis

*   Elements of the `sets[]` list are Python sets, initialized with objects
    forced to have the same `__hash__` value, based on flag characters
    `(c * 127 % 500)`. This means that, if used in a set, they will take increasingly
    longer time to access.
*   To discover each character we iterate over all possible values and try to
    add a large batch of objects with the hashes corresponding to these characters.
*   The correct character will take longer, as the set simplementation will have to
    append it to an already long list.

Additional difficulty: the input to `add_batch()` is hashed differently
(`MyNumber` vs `MyChar`), so, we need to reverse that hash. Conveniently,
`pow()` can operate in `modN` integer arithmetic too!

`BATCH_SIZE=500` seems to work optimally, sometimes just needs one extra run.

# Getting the flag

```python
import time
import pwn
import sys


def reverse_hash(c):
    needed_hash = (ord(c)*127)%500
    inv_1337 = pow(1337, -1, 500)
    return (needed_hash * inv_1337) % 500

alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_-/{}=()"
BATCH_SIZE = 500

io = pwn.remote('xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx.library.m0unt41n.ch', 1337, ssl=True)
io.recvuntilS(b"Enter the batch size :\n")
io.sendline(str(BATCH_SIZE).encode('ascii'))

print("FLAG: \033[1;37;40m", end="")
for i in range(9999):
    max_time_so_far = 0
    max_char_so_far = ''
    for c in range(0, len(alphabet)):
        io.recvuntilS(b"Enter the set number :\n")
        io.sendline(str(i).encode('ascii'))
        io.recvuntilS(b"Enter the number to store :\n")
        num = reverse_hash(alphabet[c])
        t = time.perf_counter()
        io.sendline(str(num).encode('ascii'))
        try:
            io.recvuntilS(b"Done\n")
            t = time.perf_counter()-t
            if t > max_time_so_far:
                max_time_so_far = t
                max_char_so_far = alphabet[c]
        except EOFError:
            print("\033[0;37;40m")
            io.close()
            sys.exit(0)
        io.recvuntilS(b"Do you want to continue ?\n")
        io.sendline(b"y")
    print(max_char_so_far, end="")
```

Running it:

```
[+] Opening connection to a271a963-c9de-4cfa-838f-3798545c0523.library.m0unt41n.ch on port 1337: Done
FLAG: SHC2024{WOW_NICELY_TIMED}
[*] Closed connection to a271a963-c9de-4cfa-838f-3798545c0523.library.m0unt41n.ch port 1337
```

---

## `SHC2024{WOW_NICELY_TIMED}`


<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
