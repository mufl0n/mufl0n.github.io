# treasury

[library.m0unt41n.ch/challenges/treasury](https://library.m0unt41n.ch/challenges/treasury) ![](../../resources/crypto.svg) ![](../../resources/easy.svg) 

# TL;DR

We get `treasury.py` that we talk to remotely:

```python
import json, os
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

FLAG = os.environ.get("FLAG", "flag{FAKE_FLAG}")
KEY = get_random_bytes(16)

def wrap(key: bytes, data: str) -> str:
    nonce = get_random_bytes(8)

    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    encr_data = cipher.encrypt(data.encode("utf-8"))
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    encr_time = cipher.encrypt(datetime.utcnow().isoformat().encode("utf-8"))
    return json.dumps({
        "data": encr_data.hex(),
        "time": encr_time.hex(),
        "nonce": nonce.hex()
    })

def unwrap(key: bytes, enc_json: str) -> (str, str):
    enc_data = json.loads(enc_json)
    nonce = bytes.fromhex(enc_data["nonce"])
    enc_time = bytes.fromhex(enc_data["time"])
    enc_data = bytes.fromhex(enc_data["data"])

    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    data = cipher.decrypt(enc_data)
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    time = cipher.decrypt(enc_time)
    return (data.decode("utf-8"), time.decode("utf-8"))

if __name__ == "__main__":
    print("Welcome to the treasury!")
    print("We have encrypted many different secrets already and offer")
    print("to do the same for you! One example we have here:")
    print(wrap(KEY, FLAG))

    while True:
        print("What would you like to do?")
        print(" 1. Wrap")
        print(" 2. Unwrap")
        print(" 3. Exit")
        answer = input("> ").strip()
        try:
            if answer == "1":
                data = input("Enter the data to wrap\n> ").strip()
                data = wrap(KEY, data)
                print("Its wrapped now:")
                print(data)
            if answer == "2":
                data = input("Enter the data to unwrap\n> ").strip()
                data, time = unwrap(KEY, data)
                if data == FLAG:
                    print(f"Sorry, we can't tell you what was wrapped at {time}.")
                    continue
                print(f"Data unwrapped (was created at {time}):")
                print(data)
            if answer == "3":
                print("Exiting...")
                break
        except:
            print("Something went wrong.")
```

# Key observation

The only thing preventing us from getting the flag is the
decrypted text being **exactly** the same as flag.

But, it can be **longer** &#128578; and CTR is a block cipher so, nothing prevents
us from:

*   appending some garbage to the vault contents provided at start
*   decrypting the result using "unwrap" function
*   ignoring whatever the garbage ends up being decrypted to

CTR makes it even easier, because every byte is a "block". So, even adding a
single byte (i.e. two hex characters) should be enough.

The only small nuance: the decrypted data may fail some of the
`decode("utf-8")` calls in the code - the program will just say
`Something went wrong`, but there will be an underlying
`UnicodeDecodeError`. But, we can try multiple times and the encryption key
won't change. So, it's a matter of trying.

# Exploiting

```
$ ncat --ssl xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx.library.m0unt41n.ch 1337
Welcome to the treasury!
We have encrypted many different secrets already and offer
to do the same for you! One example we have here:
{"data": "08772c262a5d4567509521b442db", "time": "7477707134322f79179510e148de6f4d2a344124dd25b27ebb96", "nonce": "8efedeeced71f2f7"}
```

This is our "wrapped" flag. Let's try decoding it with `aa` appended to `data`:

```
What would you like to do?
 1. Wrap
 2. Unwrap
 3. Exit
> 2
Enter the data to unwrap
> {"data": "08772c262a5d4567509521b442dbaa", "time": "7477707134322f79179510e148de6f4d2a344124dd25b27ebb96", "nonce": "8efedeeced71f2f7"}
Something went wrong.
```

That did not work. How about `11`?

```
What would you like to do?
 1. Wrap
 2. Unwrap
 3. Exit
> 2
Enter the data to unwrap
> {"data": "08772c262a5d4567509521b442db11", "time": "7477707134322f79179510e148de6f4d2a344124dd25b27ebb96", "nonce": "8efedeeced71f2f7"}
Data unwrapped (was created at 2024-08-25T15:44:54.111898):
N0nc3_R3u5ed??J
```

---

## `cyberskills23{N0nc3_R3u5ed??}`


<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
