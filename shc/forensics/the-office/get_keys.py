#!/usr/bin/python3

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

