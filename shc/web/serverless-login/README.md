# serverless-login

[library.m0unt41n.ch/challenges/serverless-login](https://library.m0unt41n.ch/challenges/serverless-login) ![](../../resources/web.svg) ![](../../resources/baby.svg) 

# TL;DR

A HTML page runs embedded Python code, which loads a remote SQLite database containing
a SHA256 hash of the admin password, which ends up being a well-known one.

# Solution

Looking at the source of the login page, it loads [pyscript.net](http://pyscript.net)
Python-in-a-browser interpreter (serverless! &#128522;).

That script loads a `database.db` SQLite file (locally, into the Python code executing
in the browser!!), comparing SHA256 of the input password with the one stored in that DB.

Looking at the `database.db`:

```sql
$ sqlite3 database.db
sqlite> .schema
CREATE TABLE Login (
    username VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    PRIMARY KEY (username)
);
sqlite> select * from Login;
admin|11a4a60b518bf24989d481468076e5d5982884626aed9faeb35b8576fcd223e1
```

Using a random SHA256 cracking website 
([https://10015.io/tools/sha256-encrypt-decrypt](https://10015.io/tools/sha256-encrypt-decrypt))
that's a hash of `python`.

We can now login in the app, **U:admin**, **P:python** and get the flag.

---

## `shc2024{wh0_N33d5_4_53RV3r_4nYw4Y2?}`


<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
