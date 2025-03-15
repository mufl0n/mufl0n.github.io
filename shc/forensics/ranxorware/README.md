# ranxorware

[library.m0unt41n.ch/challenges/ranxorware](https://library.m0unt41n.ch/challenges/ranxorware) ![](../../resources/forensics.svg) ![](../../resources/baby.svg) 

# TL;DR

We get an encryption program:

```python
import sys, os

def xor(data: bytes, key: bytes):
    output = bytearray()
    for i, data_byte in enumerate(data):
        output.append(data_byte ^ key[i % len(key)])
    return output

def hexlify(data: bytes):
    hexes = [f"{b:02X}" for b in data]
    return ' '.join(hexes)

if len(sys.argv) != 3:
    print(f"Usage: {sys.orig_argv[:2]} [file] [dest]", file=sys.stderr)
    exit(1)

input_file = sys.argv[1]
dest_file = sys.argv[2]

with open(input_file, 'rb') as f:
    input_data = f.read()
    
password = os.urandom(8)

print("Encrypting file...")
encrypted_data = xor(input_data, password)

print(f"Writing encrypted file to {dest_file}...")

with open(dest_file, 'wb') as f:
    f.write(encrypted_data)

password_file = dest_file + '.pw'
print(f"Saving password to {password_file}...")
with open(password_file, 'w') as f:
    f.write(hexlify(password))
    
print(f"Successfully encrypted {input_file}! Don't forget to delete {password_file} after you saved it!")
```

... and some files: `office/salaries.png.enc`, `office/salaries.png.enc.pw`, `secret/flag.png.enc`.

# Decrypting the Mario image

First attempt is of course do xor-decrypt the image in the `office` dir,
but that's not the solution - yields an image telling you so.

# Using the same key to decrypt the flag

Does not work, produces the garbage

# Get encryption key by comparing with PNG header

-   Look at first 16 bytes of encrypted flag
-   `XOR` them with expected PNG headers.
-   That yields, twice: `4E 0F 2E 29 EC 1C 10 B0`

Using these bytes to decrypt the flag, yields a PNG with QR code, which
parses as a flag.

![](flag.png "")

---

## `flag{8_8yt3_k3y_1s_n0t_3n0ugh??}`


<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
