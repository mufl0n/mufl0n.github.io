# office-encryption

[library.m0unt41n.ch/challenges/office-encryption](https://library.m0unt41n.ch/challenges/office-encryption) ![](../../resources/crypto.svg) ![](../../resources/baby.svg) 

# TL;DR

A trivial substitution encryption.

# Code

```python
from random import shuffle
from collections import Counter


def generate_substitution_cipher(text):
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    shuffled_alphabet = list(alphabet)
    shuffle(shuffled_alphabet)
    cipher_map = {
        original: substituted
        for original, substituted in zip(alphabet, shuffled_alphabet)
    }

    encrypted_text = ""
    for char in text:
        if char.lower() in cipher_map:
            encrypted_char = cipher_map[char.lower()]
            if char.isupper():
                encrypted_char = encrypted_char.upper()
            encrypted_text += encrypted_char
        else:
            encrypted_text += char

    return encrypted_text, cipher_map


text = "shc2024{fake_flag}"

encrypted_text, cipher_map = generate_substitution_cipher(text)

print(encrypted_text, cipher_map)
```

# Decryption

```python
# Copied from the cipher_map.txt
cipher_map = {'a': 'k', 'b': 'n', 'c': 'o', 'd': 'r', 'e': 'v', 'f': 'q', 'g': 'i', 'h': 'w', 'i': 'x', 'j': 'd', 'k': 'h', 'l': 'm', 'm': 'l', 'n': 'y', 'o': 'u', 'p': 'b', 'q': 'f', 'r': 'p', 's': 's', 't': 'z', 'u': 't', 'v': 'a', 'w': 'c', 'x': 'j', 'y': 'g', 'z': 'e'}

encrypted_flag = 'swo2024{jytmm_ruvs_opgbzu_mum}'

for c in encrypted_flag:
  found = False
  for m in cipher_map:
    if cipher_map[m]==c:
      print(m, end="")
      found = True
  if not found:
    print(c, end="")
print("")
```

---

## `shc2024{xnull_does_crypto_lol}`


<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
