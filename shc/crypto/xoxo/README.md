# xoxo

[library.m0unt41n.ch/challenges/xoxo](https://library.m0unt41n.ch/challenges/xoxo) ![](../../resources/crypto.svg) ![](../../resources/baby.svg) 

# TL;DR

We get a XOR-encrypted flag, with the source for encryption program.

# Code

```python
import random
from pwn import xor

def gen_key():
    KEY_128_BIT = 128 % 15
    KEY = random.getrandbits(KEY_128_BIT)
    return KEY

def encrypt(message):
    KEY = gen_key()
    return xor(message, KEY)

print(encrypt(b"SCD{fake_flag}"))
```

Encrypted flag:

```
b'\x8c\x9c\x9b\xa4\xa7\xef\xad\x80\xbd\xad\xaa\xab\xec\x80\xec\xe6\xbd\xba\xef\xed\xb9\xb9\xa2'
```

# Getting the flag

We know that

*   `KEY` is 8-bit (`128 % 15 == 8`)
*   The flag starts with `S` and it's "encrypted" to `0x8C`.

```python
from pwn import xor
output = b'\x8c\x9c\x9b\xa4\xa7\xef\xad\x80\xbd\xad\xaa\xab\xec\x80\xec\xe6\xbd\xba\xef\xed\xb9\xb9\xa2'
key = 0x8c ^ ord('S')
print(xor(output, key).decode('ascii'))
```

---

## `SCD{x0r_brut3_39be02ff}`


<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
