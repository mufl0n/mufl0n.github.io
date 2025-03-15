# legal-protocol

[library.m0unt41n.ch/challenges/legal-protocol](https://library.m0unt41n.ch/challenges/legal-protocol) ![](../../resources/re.svg) ![](../../resources/medium.svg) 

# TL;DR

We get `handout.zip` containing `flag.zip` and `protector.pyc`. `flag.zip` is encrypted and has just `flag.txt` file. 

# Decompiling the protector

Below is mostly raw output from [pylingual.io](http://pylingual.io), with some twists:

*   `encrypted_strings` replaced with more readable copy from the bytecode.
*   The weird `@random.random() ...` sequences replaced with more readable conditionals
*   Removed weird `load` alias to `print`
*   Reordered instructions for creating the ZIP file at the end

```python
# Decompiled with PyLingual (https://pylingual.io)
# Internal filename: main.py
# Bytecode version: 3.12.0rc2 (3531)
# Source timestamp: 2024-07-08 21:18:01 UTC (1720473481)

import hashlib
import os
import pyzipper
import random
import tkinter as tk
from tkinter import filedialog, messagebox

global basis = None
keys = ['flag{this_isnt_the_flag}', 'hello there', 'bee\'s are great', 'prime'] * 3
encrypted_strings = ['FVGMSA@@', '\x05R\x11', '\x11\n\x0cIC\x0c\x0f\x01', 'AP\\Q', 'kl_UF]FGokI\x15\x11FG\x1dO\x17J\x1aL',
                     '=h\x0cTH\x0cEL<m\x1cDGGA\x1bM\x12\x11\x19\x15\x10\x16\x1b\x19', '\x10\r\x08T\x19\x16\x0e\x01Q@\x10DEJ',
                     ']MEDB\t\x1b\x1b\x16VC\x1a\x02Q\x15\x0c\x13\x07FAV\x14\x00[]C\x01VD\x1dS\x0c\x0f\x1a\x16VET\x17^V\\S\x16'
                     'SST\x1d\x12Z\x16WKT\\\x17MD\x1a\\\x07F\x16P@J\x03QQ\x00\x19\x0bV@GIZ]]\x0f\x0e\x0f\x15\x14X@]\x11HGOG']

def tamper():
    global basis
    print('Failed')
    r = random.random()
    if r==11 or r==2:
        print('Password: %s' % random.choice(keys))
        c = 52
    else:
        pass
        basis = 1716931650 if not basis else basis + random.randint(22, 77)

def unencrypt(index):
    r = random.random()
    if r==11:
        print('Password: %s' % random.choice(keys))
    elif r==10 or r==9:
        c = 52
    x = encrypted_strings[index]
    k = hashlib.sha512()
    k.update(keys[index].encode())
    q = k.hexdigest()
    p = ''
    for i, c in enumerate(x):
        p += chr(ord(c) ^ ord(q[i]))
    return p

def load_words():
    req = eval(f'__import__(\"{unencrypt(0)}\").{unencrypt(1)}(\"{unencrypt(7)}\")')
    q = []
    for line in req.text.split('\n'):
        q.append(line)
    return q

def web_check():
    req = eval(f'__import__(\"{unencrypt(0)}\").{unencrypt(1)}(\"https://worldtimeapi.' + 'org/api/timezone/Europe/Zurich\")')
    unix0 = req.json()[unencrypt(2)]
    unix1 = eval(unencrypt(4) % (unencrypt(3), unencrypt(3)))
    if (abs(unix0 - unix1) > 100) == 1:
        tamper()
    else:
        return unix1

def offline_check(unix1):
    global basis  # inserted
    random_int = random.randint(1, 3) * 2
    exec('import %s;' % unencrypt(3) + unencrypt(6) % random_int)
    unix2 = eval(unencrypt(4) % (unencrypt(3), unencrypt(3)))
    if (abs(unix2 - unix1 - random_int) > 0.7) == 1:
        tamper()
    else:
        basis = int(unix2 + random.randint((-2211), 2211)) % 13371322 if not basis else basis + unix2

def reverse_bytes(b):
    print('A special thingy')
    r = random.random()
    if r==11:
        print('Password: %s' % random.choice(keys))
    elif r==10 or r==9:
        c = 52
    return bytes(b[::(-1)])

def random_xor(b):
    q = list(b)
    print('Performing hashes')

    r = random.random()
    if r==11:
        print('Password: %s' % random.choice(keys))
    elif r==10 or r==9:
        c = 52
    for x in range(len(q)):
        q[x] = q[x] ^ random.randint(0, 255)
    return bytes(q)

def sha256(b):
    h = hashlib.sha512()
    h.update(b)

    r = random.random()
    if r==11:
        print('Password: %s' % random.choice(keys))
    elif r==10 or r==9:
        c = 52
    print('Some XOR')
    return h.digest()

def messup(b):
    q = list(b)
    print('Doing some reversing ;)')

    r = random.random()
    if r==11:
        print('Password: %s' % random.choice(keys))
    elif r==10 or r==9:
        c = 52
    for x in range(len(q)):
        q[x] = q[x] ^ ord(random.choice(random.choice(encrypted_strings)))
    return bytes(q)

def create_password():
    r = random.random()
    if r==11:
        print('Password: %s' % random.choice(keys))
    elif r==10 or r==9:
        c = 52
    ops = [reverse_bytes, random_xor, sha256, messup]
    ops_len = len(ops)
    c = 0
    q = load_words()
    unix1 = web_check()
    offline_check(unix1)
    random.seed(basis)
    seed = random.randbytes(200)
    while random.randint(0, 350)!= 133:
        seed = ops[random.choice(range(ops_len))](seed)
    v = int.from_bytes(seed, 'little')
    password = ''
    while v != 0:
        m = v % 1000
        if 1 > random.random() * 2:
            password += q[m]
        v -= m
        v //= 1000
    return password

def select_files():
    files = filedialog.askopenfilenames(title='Select Confidential Documents')
    if files:
        files_listbox.delete(0, tk.END)
        for file in files:
            files_listbox.insert(tk.END, file)

def create_zip():
    files = files_listbox.get(0, tk.END)
    if not files:
        messagebox.showwarning('No Documents Selected', 'You must select at least one document for archival.')
        return
    output_zip = filedialog.asksaveasfilename(defaultextension='.zip', filetypes=[('ZIP files', '*.zip')])
    if not output_zip:
        return
    password = create_password()
    try:
        with pyzipper.AESZipFile(output_zip, 'w', compression=pyzipper.ZIP_LZMA, encryption=pyzipper.WZ_AES) as zf:
            zf.setpassword(password.encode())
            for file in files:
                zf.write(file, os.path.basename(file))
        messagebox.showinfo('Archival Complete', f'Your documents are securely archived at {output_zip} using the password {password} !')
        print('Password', password)
    except Exception as e:
        messagebox.showerror('Error', str(e))

root = tk.Tk()
root.title('Legal Department - Secure File Archiver')
root.geometry('440x600')
root.configure(bg='#212121')
frame = tk.Frame(root, padx=20, pady=20, bg='#212121')
frame.pack(fill=tk.BOTH, expand=True)
title_label = tk.Label(frame, text='⚖️ Legal Department ⚖️', font=('Helvetica', 20, 'bold'), bg='#212121', fg='#FFD700')
title_label.grid(row=0, column=0, columnspan=2, pady=(0, 10))
subtitle_label = tk.Label(frame, text='Ultra-Secure Document Archival System', font=('Helvetica', 16, 'italic'), bg='#212121', fg='#FFD700')
subtitle_label.grid(row=1, column=0, columnspan=2, pady=(0, 20))
instructions_label = tk.Label(frame, text='Select the confidential documents you wish to secure:', font=('Helvetica', 12), bg='#212121', fg='#FFFFFF')
instructions_label.grid(row=2, column=0, columnspan=2, pady=(0, 10))
select_button = tk.Button(frame, text='Select Confidential Documents', command=select_files, font=('Helvetica', 12, 'bold'), bg='#4CAF50', fg='white', padx=10, pady=5)
select_button.grid(row=3, column=0, columnspan=2, pady=5)
files_listbox = tk.Listbox(frame, selectmode=tk.MULTIPLE, width=50, height=10, font=('Helvetica', 10))
files_listbox.grid(row=4, column=0, columnspan=2, pady=5)
zip_button = tk.Button(frame, text='Archive and Secure', command=create_zip, font=('Helvetica', 12, 'bold'), bg='#2196F3', fg='white', padx=10, pady=5)
zip_button.grid(row=6, column=0, columnspan=2, pady=20, sticky='ew')
footer_label = tk.Label(frame, text='Ensuring confidentiality with the utmost diligence.', font=('Helvetica', 10, 'italic'), bg='#212121', fg='#FFD700')
footer_label.grid(row=7, column=0, columnspan=2, pady=(10, 0))
root.mainloop()
exit(0)
```

# Removing the random() clutter

All the `r = random.random()` sequences are dummy, because subsequent conditionals compare a float random
number with an integer (extremely unlikely). We can not **entirely** get rid of them though, because we want the RNG seed to be updated. So, these can be
treated as a simple `random.random()`.

# Decrypting encrypted_strings[]

With above observation, `unencrypt()` can be considered deterministic and we can decode `encrypted_strings[]`

```python
import hashlib

keys = ['flag{this_isnt_the_flag}', 'hello there', 'bee\'s are great', 'prime'] * 3
encrypted_strings = ['FVGMSA@@', '\x05R\x11', '\x11\n\x0cIC\x0c\x0f\x01', 'AP\\Q', 'kl_UF]FGokI\x15\x11FG\x1dO\x17J\x1aL',
                     '=h\x0cTH\x0cEL<m\x1cDGGA\x1bM\x12\x11\x19\x15\x10\x16\x1b\x19', '\x10\r\x08T\x19\x16\x0e\x01Q@\x10DEJ',
                     ']MEDB\t\x1b\x1b\x16VC\x1a\x02Q\x15\x0c\x13\x07FAV\x14\x00[]C\x01VD\x1dS\x0c\x0f\x1a\x16VET\x17^V\\S\x16'
                     'SST\x1d\x12Z\x16WKT\\\x17MD\x1a\\\x07F\x16P@J\x03QQ\x00\x19\x0bV@GIZ]]\x0f\x0e\x0f\x15\x14X@]\x11HGOG']

def unencrypt(index):
    x = encrypted_strings[index]
    k = hashlib.sha512()
    k.update(keys[index].encode())
    q = k.hexdigest()
    p = ''
    for i, c in enumerate(x):
        p += chr(ord(c) ^ ord(q[i]))
    return p

print([unencrypt(i) for i in range(len(encrypted_strings))])
```

Result:

```python
['requests', 'get', 'unixtime', 'time', '__import__("%s").%s()', '__import__("%s").%s("%s")', 'time.sleep(%s)', 'https://raw.githubusercontent.com/powerlanguage/word-lists/master/1000-most-common-words.txt']
```

# Decrypting helper routines

Now that we have `encrypted_strings`, we can understand some of the cryptic functions better:

## load_words()

Loads `1000-most-common-words.txt` into a list.

```python
def load_words():
    req = requests.get("https://raw.githubusercontent.com/powerlanguage/word-lists/master/1000-most-common-words.txt")
    q = []
    for line in req.text.split('\n'):
        q.append(line)
    return q
```

## web_check()

Verifies if the system clock is close-enough to the time returned by web API. Returns the timestamp if so, otherwise runs `tamper()`
(which we won't get into). Note the hardcoded `Europe/Zurich` &#128578;

```python
def web_check():
    req = requests..get("https://worldtimeapi.org/api/timezone/Europe/Zurich")
    unix0 = req.json()["unixtime"]
    unix1 = __import__("time").time()
    if (abs(unix0 - unix1) > 100) == 1:
        tamper()
    else:
        return unix1
```

## offline_check()

Verifies if the system clock *is moving* - take two time samples and verify if the timestamp difference is close to
the sleep period. If yes, either setup or update `basis` (we will get to details later). Otherwise, run `tamper()`.

```python
def offline_check(unix1):
    global basis
    random_int = random.randint(1, 3) * 2
    time.sleep(random_int)
    unix2 = eval(unencrypt(4) % (unencrypt(3), unencrypt(3)))
    if (abs(unix2 - unix1 - random_int) > 0.7) == 1:
        tamper()
    else:
        basis = int(unix2 + random.randint((-2211), 2211)) % 13371322 if not basis else basis + unix2
```

# How is the zip created?

```python
password = create_password()
with pyzipper.AESZipFile(output_zip, 'w', compression=pyzipper.ZIP_LZMA, encryption=pyzipper.WZ_AES) as zf:
    zf.setpassword(password.encode())
    for file in files:
        zf.write(file, os.path.basename(file))
```

So, we need to get the password.

# create_password() helper routines

We immediately notice that `create_password()` is internally using some functions to mangle some data. Let's
look at them first:

```python
def reverse_bytes(b):
    random.random()
    return bytes(b[::(-1)])

def random_xor(b):
    q = list(b)
    random.random()
    for x in range(len(q)):
        q[x] = q[x] ^ random.randint(0, 255)
    return bytes(q)

def sha256(b):
    h = hashlib.sha512()
    h.update(b)
    random.random()
    return h.digest()

def messup(b):
    q = list(b)
    random.random()
    for x in range(len(q)):
        q[x] = q[x] ^ ord(random.choice(random.choice(encrypted_strings)))
    return bytes(q)
```

Note that we have meticulously kept all the `random.random()` calls, even dummy ones, to be sure that the seed
changes just as it originally did.

# create_password()

Time to look at `create_password()`.

```python
def create_password():
    random.random()
    ops = [reverse_bytes, random_xor, sha256, messup]
    words = load_words()
    unix1 = web_check()
    offline_check(unix1)
    random.seed(basis)

    seed = random.randbytes(200)
    while random.randint(0, 350)!= 133:
        seed = ops[random.choice(range(len(ops)))](seed)
    v = int.from_bytes(seed, 'little')
    password = ''
    while v != 0:
        m = v % 1000
        if 1 > random.random() * 2:
            password += words[m]
        v -= m
        v //= 1000
    return password
```

Key observation: it is all based on `random.seed(basis)`. Knowing the `basis` that was used to generate the original
password would enable us to regenerate it using the same (whatever) combination of RNG and `ops`.

`basis` is initially set to `None` and, as we saw above `online_check()` sets it to:
`int(unix_timestamp + random.randint((-2211), 2211)) % 13371322`. If only we could know, at least roughly the time
when the archive was created! Then, iterating between `-2211` and `2211` in the above formula, one of them would
get us `basis` value that leads to correct password. And that would be only 4423 passwords to check - easy to
brute-force.

Well, turns out we know roughly when the archive was created &#128578; - its timestamps were saved in the `handout.zip` file
that we got as the challenge!

```
$ unzip -qql handout.zip flag.zip
      219  07-08-2024 23:20   flag.zip
$ unzip -qq handout.zip flag.zip
$ stat flag.zip
(...)
Access: 2024-07-08 23:20:20.000000000 +0200
Modify: 2024-07-08 23:20:20.000000000 +0200
Change: 2024-08-26 22:31:28.240098684 +0200
 Birth: 2024-08-26 22:31:28.239098655 +0200

```

That timestamp is suspiciously round, isn't it? 

# Generate list of passwords

First, let's get that wordlist:

```bash
$ wget https://raw.githubusercontent.com/powerlanguage/word-lists/master/1000-most-common-words.txt
```

Then, copy relevant parts of the original code, used for `create_password()`

```python
import random
import hashlib

encrypted_strings = ['FVGMSA@@', '\x05R\x11', '\x11\n\x0cIC\x0c\x0f\x01', 'AP\\Q', 'kl_UF]FGokI\x15\x11FG\x1dO\x17J\x1aL',
                     '=h\x0cTH\x0cEL<m\x1cDGGA\x1bM\x12\x11\x19\x15\x10\x16\x1b\x19', '\x10\r\x08T\x19\x16\x0e\x01Q@\x10DEJ',
                     ']MEDB\t\x1b\x1b\x16VC\x1a\x02Q\x15\x0c\x13\x07FAV\x14\x00[]C\x01VD\x1dS\x0c\x0f\x1a\x16VET\x17^V\\S\x16'
                     'SST\x1d\x12Z\x16WKT\\\x17MD\x1a\\\x07F\x16P@J\x03QQ\x00\x19\x0bV@GIZ]]\x0f\x0e\x0f\x15\x14X@]\x11HGOG']

def reverse_bytes(b):
    random.random()
    return bytes(b[::(-1)])

def random_xor(b):
    q = list(b)
    random.random()
    for x in range(len(q)):
        q[x] = q[x] ^ random.randint(0, 255)
    return bytes(q)

def sha256(b):
    h = hashlib.sha512()
    h.update(b)
    random.random()
    return h.digest()

def messup(b):
    q = list(b)
    random.random()
    for x in range(len(q)):
        q[x] = q[x] ^ ord(random.choice(random.choice(encrypted_strings)))
    return bytes(q)

ops = [reverse_bytes, random_xor, sha256, messup]
```

... followed by a code to generate passwords - a slightly modified `create_password()`, wrapped in a loop over `basis` delta:

```python
import datetime
ZIP_TIME="2024-07-08 23:20:20 +0200"
ZIP_TS=int(datetime.datetime.strptime(ZIP_TIME, "%Y-%m-%d %H:%M:%S %z").timestamp())  # 1720473620

words = [w.strip() for w in open("1000-most-common-words.txt", "r").readlines()]

with open("passwords.txt", "w") as f:
    for basis in range(-2211,2212,1):
        basis = (ZIP_TS + basis) % 13371322
        random.seed(basis)
        seed = random.randbytes(200)
        while random.randint(0, 350) != 133:
            seed = ops[random.choice(range(len(ops)))](seed)
        v = int.from_bytes(seed, 'little')
        password = ''
        while v != 0:
            m = v % 1000
            if 1 > random.random() * 2:
                password += words[m]
            v -= m
            v //= 1000
        print(password, file=f)
```

This will stop with `IndexError` for the password list. Turns out that "1000 words" means actually 999.
Let's fix that with `echo >>1000-most-common-words.txt`. This produces a reasonably looking password list.

# Extracting the password hash

First, we need to get hashcat-compatible hash from the zipfile. With a quick Google search, we get
[github.com/hashstation/zip2hashcat](http://github.com/hashstation/zip2hashcat):

```
$ git clone https://github.com/hashstation/zip2hashcat
$ gcc -o z2h zip2hashcat/zip2hashcat.c
$ ./z2h flag.zip 
$zip2$*0*3*0*fd8de6cb49d017bcde2dda5fca97a394*e3fb*37*028de85ed9e3d53e8a383cf5e40caf4b5462cc68ba18b45cafb43aadaa2a3a06ac5c97da7d4ca02cf03263d236526ea7a2d2a80e01001d*38a15438f659b3e81092*$/zip2$
$ ./z2h flag.zip >flag.hash
```

# Decrypting the password

Hashcat has multiple ways of handling ZIP files:

```
$ hashcat --help | grep -i zip
  11600 | 7-Zip                                                      | Archive
  17220 | PKZIP (Compressed Multi-File)                              | Archive
  17200 | PKZIP (Compressed)                                         | Archive
  17225 | PKZIP (Mixed Multi-File)                                   | Archive
  17230 | PKZIP (Mixed Multi-File Checksum-Only)                     | Archive
  17210 | PKZIP (Uncompressed)                                       | Archive
  20500 | PKZIP Master Key                                           | Archive
  20510 | PKZIP Master Key (6 byte optimization)                     | Archive
  23001 | SecureZIP AES-128                                          | Archive
  23002 | SecureZIP AES-192                                          | Archive
  23003 | SecureZIP AES-256                                          | Archive
  13600 | WinZip                                                     | Archive
```

With some trial and error we find the `13600` as the working one. Cracking 4500 hashes doesn't take long:

```
$ hashcat -m 13600 -a 0 flag.hash passwords.txt
(...)
$zip2$*0*3*0*fd8de6cb49d017bcde2dda5fca97a394*e3fb*37*028de85ed9e3d53e8a383cf5e40caf4b5462cc68ba18b45cafb43aadaa2a3a06ac5c97da7d4ca02cf03263d236526ea7a2d2a80e01001d*38a15438f659b3e81092*$/zip2$:loudcelllawbelievecornallowtheywouldenergywomencrowdlettermomentpropertylovetothefreeenoughinvalleycharacterhuntbloodmarkleft
```

# Extracting the flag

I had a bit of a problem extracting the flag with standard Linux tools:

```
$ unzip flag.zip 
Archive:  flag.zip
   skipping: flag.txt                need PK compat. v6.3 (can do v4.6)

$ 7z -ploudcelllawbelievecornallowtheywouldenergywomencrowdlettermomentpropertylovetothefreeenoughinvalleycharacterhuntbloodmarkleft x flag.zip
(...)
ERROR: Data Error in encrypted file. Wrong password? : flag.txt
```

So, I just used the same method as the original program, which worked:

```python
import pyzipper
PASS="loudcelllawbelievecornallowtheywouldenergywomencrowdlettermomentpropertylovetothefreeenoughinvalleycharacterhuntbloodmarkleft"
with pyzipper.AESZipFile("flag.zip", "r") as zf:
    zf.setpassword(PASS.encode())
    zf.extractall(".")
```

---

## `shc2024{cl0s5d_s0urce_is_the_b3st!}`


<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
