#!/usr/bin/python3
import socket

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_socket.bind(('0.0.0.0', 80))
server_socket.listen(1)

while True:
    connection, client_address = server_socket.accept()
    data = connection.recv(10240)
    reply = b"Move along, nothing to see here"
    if b"message:" in data:
        data = data[data.find(b"message:")+len(b"message:"):]
        data = data[:data.find(b':')].decode('ascii')
        reply = b' <message>'+bytes.fromhex(data)+b'</message> '
    print("Sending: "+repr(reply))
    connection.sendall(reply)
    connection.close()
