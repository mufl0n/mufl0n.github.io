#!/usr/bin/python3
from socket import *

sock = socket(AF_INET, SOCK_STREAM)
sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
sock.bind(('0.0.0.0', 6666))
sock.listen(1)
while True:
    print("\n[FILTER AWAITING CONNECTIONS]")
    (con, client) = sock.accept()
    print("[FILTER CONNECTION FROM:", client,"]")
    data = con.recv(10240)
    if len(data)==0:
        con.close()
        print("Connection closed")
        break
    print("[FILTER RECEIVED: ", data, "]")
    for i in range(len(data)):
        if data[i]==0:
            data = data[:i]
            break
    print("[FILTER SENDING BACK: ", data, "]")
    con.send(data)
    con.close()
