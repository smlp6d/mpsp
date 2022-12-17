import socket


class builder:
    def __init__(self, addr: str = '', port: int = 9000):
        self.s = socket.socket()
        self.addr = addr
        self.port = port

    def server(self):
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s.bind((self.addr, self.port))
        self.s.listen()

        return self.s

    def client(self):
        self.s.connect((self.addr, self.port))

        return self.s
