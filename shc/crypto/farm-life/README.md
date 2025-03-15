# farm-life

[library.m0unt41n.ch/challenges/farm-life](https://library.m0unt41n.ch/challenges/farm-life) ![](../../resources/crypto.svg) ![](../../resources/easy.svg) 

# TL;DR

We get a simple XOR-based encrypted vault:

```python
#!/usr/bin/env python3
import secrets

FLAG = "shc2024{FAKE_FLAG}"

def encrypt(key, plaintext):
    return ''.join(str(int(a) ^ int(b)) for a, b in zip(key, plaintext))


def main():
    # keygen
    key = format(secrets.randbits(365), 'b')
    print("Welcome to the CryptoFarm!")
    while True:
        command = input('Would you like to encrypt a message yourself [1], get the flag [2], or exit [3] \n>').strip()
        try:
            if command == "1":
                data = input('Enter the binary string you want to encrypt \n>')
                print("Ciphertext = ", encrypt(key, data))
                key = format(secrets.randbits(365), 'b')
            elif command == "2":
                print("Flag = ", encrypt(key, format(int.from_bytes(FLAG.encode(), 'big'), 'b')))
            elif command == "3":
                print("Exiting...")
                break
            else:
                print("Please enter a valid input")
        except Exception:
            print("Something went wrong.")

if __name__ == "__main__":
    main()
```

The program generates a random bitstring and then, uses it for encryption during the session.

We have options to encrypt arbitrary binary string and get an encrypted flag.

# Getting the flag

*   Request encoded flag bitstring
*   Encrypt a string of zeros, with identical length
*   Encrypted results will be the key
*   Use that key to decrypt the flag

# Solution

Let's document it properly with a [pwntools](https://github.com/Gallopsled/pwntools) exploit anyway. First, starting the "server":

```bash
$ socat TCP-LISTEN:5000,reuseaddr,fork EXEC:"python otp_public.py"
```

## Exploit

```python
#!/usr/bin/python
import pwn
import re

pwn.context.encoding='ascii'

con = pwn.remote('127.0.0.1', 5000, ssl=False)

# Initial banner
print(con.recvuntilS(">")+"2")

# Get encrypted flag
con.sendline("2")
s = con.recvuntilS(">")
flag_enc = re.compile(r"(Flag = +)([01]+)", re.MULTILINE).search(s).group(2)

# Encrypt a bunch of zeros
zeros = "0" * len(flag_enc)
print(s+"1")
con.sendline("1")
print(con.recvuntilS(">")+zeros)
con.sendline(zeros)

# Receive the encrypted key
s = con.recvuntilS(">")
key = re.compile(r"(Ciphertext = +)([01]+)", re.MULTILINE).search(s).group(2)

# Be nice and exit
print(s+"3")
con.sendline("3")
print(con.recvS().rstrip())
con.close()

# Decrypt the flag
d = int(flag_enc,2) ^ int(key,2)
s = ''
while d != 0:
  s += chr(d&0xFF)
  d = d>>8

# Print the flag
print("\nFlag: "+s[::-1]+"\n")
```

## Running it locally

```
$  ./get_flag.py 
[+] Opening connection to 127.0.0.1 on port 5000: Done
Welcome to the CryptoFarm!
Would you like to encrypt a message yourself [1], get the flag [2], or exit [3] 
>2
Flag =  00001000111011000011110001001100000011101001011001110100001111101011000101011111011011100111001111100000100110011011110111011011000001001110110
Would you like to encrypt a message yourself [1], get the flag [2], or exit [3] 
>1
Enter the binary string you want to encrypt 
>00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
Ciphertext =  11101110001111001111101000101000011011101111001000011100110010000011110111011101111110001111100101011110000101010010010101011001100010100001011
Would you like to encrypt a message yourself [1], get the flag [2], or exit [3] 
>3
Exiting...
[*] Closed connection to 127.0.0.1 port 5000

Flag: shc2024{FAKE_FLAG}
```

## Getting the flag

Then, running against the remote system:

```python
pwn.remote('12345678-1234-1234-1234-123456789abc.ctf.m0unt41n.ch', 1337, ssl=True)
```

---

## `shc2024{Old_Venona_Had_A_KEY_Eeieeioh}`


<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
