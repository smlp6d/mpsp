from json import loads, dumps

import rsa


class mps:
    def __init__(
            self,
            sock, encoding: str = 'utf-8', package_max_size: int = 1000, proto_name: str = 'mps',
            split_symbol: str = '$',
            config_encoding: str = 'utf-8', config_p0_size: int = 1000,
            key_size: int = 512
    ):
        self.sock = sock
        self.size = package_max_size
        self.name = proto_name
        self.split = split_symbol
        self.encoding = encoding
        self.config_p0_size = config_p0_size
        self.config_encoding = config_encoding

        self.key_size = key_size
        (self.pub_key, self.pri_key) = rsa.newkeys(key_size)
        self.pubkey_pem = self.pub_key.save_pkcs1()

    def set_handshake(self):
        config = dumps({
            'size': self.size, 'name': self.name, 'split': self.split, 'encoding': self.encoding,
            'key_size': self.key_size
        }).encode(self.config_encoding)

        p0 = '$'.join([self.name, 'co', str(len(config))]).encode(self.config_encoding)

        if self.config_p0_size - len(p0):
            self.sock.send(p0 + b' ' * (self.config_p0_size - len(p0)))
            self.sock.send(config)

            self.send_raw(self.pubkey_pem, False)
            self.shake_pubkey = rsa.PublicKey.load_pkcs1(self.recv_raw(False), 'PEM')

            return True
        else:
            return False

    def get_handshake(self):
        p0 = self.sock.recv(self.config_p0_size).decode(self.config_encoding).split('$')

        if p0[1] != 'co':
            return False
        else:
            config = loads(self.sock.recv(int(p0[2])).decode(self.config_encoding))

            self.size = config['size']
            self.name = config['name']
            self.split = config['split']
            self.encoding = config['encoding']

            if self.key_size != config['key_size']:
                self.key_size = config['key_size']
                (self.pub_key, self.pri_key) = rsa.newkeys(config['key_size'])
                self.pubkey_pem = self.pub_key.save_pkcs1()

            self.shake_pubkey = rsa.PublicKey.load_pkcs1(self.recv_raw(False), 'PEM')
            self.send_raw(self.pubkey_pem, False)

            return True

    def encode_data(self, data):
        block_size = int(self.key_size / 8 - 11)
        blocks = []

        for i in range(0, len(data), block_size):
            if len(data) - i >= block_size:
                blocks.append(data[i:i+block_size])
            else:
                blocks.append(data[i:])

        for i in range(len(blocks)):
            blocks[i] = rsa.encrypt(blocks[i], self.shake_pubkey)

        return b''.join(blocks)

    def decode_data(self, data):
        block_size = int(self.key_size / 8)
        blocks = []

        for i in range(0, len(data), block_size):
            if len(data) - i >= block_size:
                blocks.append(data[i:i + block_size])
            else:
                blocks.append(data[i:])

        for i in range(len(blocks)):
            blocks[i] = rsa.decrypt(blocks[i], self.pri_key)

        return b''.join(blocks)

    def send_raw(self, data, encrypted=True):
        packs = []

        if encrypted:
            data = self.encode_data(data)

        header = self.split.join([self.name, 'tr', str(len(data)), '']).encode(self.encoding)

        if len(header) > self.size:
            return False
        elif len(data + header) <= self.size:
            packs.append(header + data + b' ' * (self.size - len(data + header)))
        else:
            transferred = self.size - len(header)
            packs.append(header + data[:transferred])

            while transferred < len(data):
                packs.append(data[transferred:transferred + self.size])
                transferred += self.size

        for pack in packs:
            self.sock.send(pack)
        return True

    def send(self, data, encrypted=True):
        return self.send_raw(data.encode(self.encoding), encrypted)

    def recv_raw(self, encrypted=True):
        p0 = self.sock.recv(self.size).split(self.split.encode(self.encoding))

        if p0[1] != b'tr':
            return False
        else:
            data = self.split.encode(self.encoding).join(p0[3:])

            data_length = int(p0[2].decode(self.encoding))

            while len(data) < data_length:
                if data_length - len(data) > self.size:
                    data += self.sock.recv(self.size)
                else:
                    data += self.sock.recv(data_length - len(data))

            if encrypted:
                return self.decode_data(data[:data_length])
            else:
                return data[:data_length]

    def recv(self, encrypted=True):
        return self.recv_raw(encrypted).decode(self.encoding)

    def close(self):
        self.sock.close()
