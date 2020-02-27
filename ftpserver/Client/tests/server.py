import socket


sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

sk.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

sk.bind(('', 8080))

sk.listen(5)

conn, addr = sk.accept()

while 1:
    data = conn.recv(1024)
    if not data:
        break
    print(data)
