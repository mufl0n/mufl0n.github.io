# pollpals

[library.m0unt41n.ch/challenges/pollpals](https://library.m0unt41n.ch/challenges/pollpals) ![](../../resources/web.svg) ![](../../resources/easy.svg) 

# TL;DR

We get an online polling application, written in node.js.

# Analysis

The annoyance is that we don't have much way of debugging offline, as it needs
a DB. That could be probably reproduced, but, for starters, let's assume that
we will debug fully remotely.

To get a flag we have to log in as admin and then, use `/admin/flag` header.

The app does not have any reasonable SQL injection vectors.

# Cookie verification

However, the admin cookie verification (`isAdmin` in `auth.js`) seems a bit
weak. The cookie is a standard JWT cookie and saved from `/login` handler
in `app.js`:

```js
if (result) {
    const token = jwt.sign({ username: username, isAdmin: true }, jwtSecretKey, { algorithm: 'HS512', expiresIn: '5m' });
    res.cookie('polls', token, { httpOnly: true, maxAge: 3600000 });
    return res.redirect('/admin/');
}
```

So far so good. But the verification looks sloppy. In `auth.js`:

```js
function isAdmin(req, res, next) {
    const startTime = Date.now();
    const token = req.cookies.polls;

    if (!token) {
      handleInvalidCredentials(startTime, res, 'Unauthorized');
      return false;
    }

    const parts = token.split('.');
    if (parts.length !== 3) {
      handleInvalidCredentials(startTime, res, 'Unauthorized');
      return false;
    }

    const header = JSON.parse(Buffer.from(parts[0], 'base64').toString('utf8'));
    const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString('utf8'));

    if (header.alg !== 'HS512' || header.typ !== 'JWT' || !payload.exp) {
      handleInvalidCredentials(startTime, res, 'Unauthorized');
      return false;
    }

    if (payload.exp * 1000 < Date.now()) {
      handleInvalidCredentials(startTime, res, 'Token expired');
      return false;
    }

    const { username, isAdmin } = payload;

    if (username.includes('admin') && isAdmin === true) {
        next();
    } else {
        handleInvalidCredentials(startTime, res, 'Unauthorized');
        return false;
    }
}
```

What it does:

*   Read `polls` cookie
*   Split it into `header` and `payload` - **and** ignore the 3rd part
    (signature) which is already suspicious.
*   Parse base64 header and payload
*   Verify algorithm (`HS512`) cookie type (`JWT`) and that the payload has
    expiration date (`exp`)
*   Check the expiration date
*   Check `username` and `isAdmin` from the payload.

# Exploiting it

With no signature verification, we can easily forge such cookie ourselves!
Tools used:

*   [JSON Web Token Generator](https://www.lddgo.net/en/encrypt/jwt-generate)
    *   **Basic**:
        *   Category: `JWT (JWS)`
        *   Algorithm: `HS512`
        *   Type: `JWT`
    *   **Registered Claim**
        *   Expiration Time: (pick few days in the future)
    *   **Custom Claim**
    
        ```
        {
            "username": "admin",
            "isAdmin": true
        }
        ```
    *   **Secret** - can be anything (remember, we don't verify the signature)
    *   Press **Encode** to get the cookie string
*   [Cookie-Editor Firefox addon](https://addons.mozilla.org/en-US/firefox/addon/cookie-editor)
    *   There, we just create `polls` cookie, with contents copied from above.

With that, we can go to `/admin` URL and then, to `/admin/flag` too.

---

## `flag{cookie_monster_jwt_nibbler}`


<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
