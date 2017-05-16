from collections import namedtuple
import socket
import os
import base64
import hashlib
from Crypto import Random
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA


PROTO_VERSION = "mainnnet0009"
MINER_VERSION_ROOT = "morty"

MONITOR_PORT = 5654
POOL_PORT = 5659
STRIKE_TIME = 60
STRIKE_COUNT = 3
CONNECT_TIMEOUT = 5

MINER_TUNE_GOAL = 10
MINER_TUNE_HISTORY = 10


MinerJob = namedtuple('MinerJob', ('diff', 'address', 'block'))
MinerResult = namedtuple('MinerResult', ('diff', 'address', 'block', 'nonce'))

IpPort = namedtuple('IpPort', ('ip', 'port'))


class Identity(object):
    def __init__(self, keyfile=None, keydata=None):
        if keyfile and keydata is None:
            if not os.path.exists(keyfile):
                random_generator = Random.new().read
                secret = RSA.generate(1024, random_generator)
                with open(keyfile, 'wb') as handle:
                    handle.write(str(secret.exportKey()))
            else:
                with open(keyfile, 'rb') as handle:
                    keydata = handle.read()
        if keydata:
            secret = RSA.importKey(keydata)

        self.secret = secret
        self.public = secret.publickey()
        public_key_readable = str(self.public.exportKey())
        self.public_key_hashed = base64.b64encode(public_key_readable)
        self.address = hashlib.sha224(self.public_key_hashed).hexdigest()
        self.signer = PKCS1_v1_5.new(self.secret)

    def sign(self, data):
        return base64.b64encode(self.signer.sign(data))


class ProtocolBase(object):
    def __init__(self, sock, manager):
        self.sockaddr = IpPort(*sock.getpeername())
        self.sock = sock
        self.manager = manager

    def _send(self, *args):
        for data in args:
            data = str(data)
            self.sock.sendall((str(len(data))).zfill(10))
            self.sock.sendall(data)

    def _recv(self, datalen=10):
        data = self.sock.recv(datalen)
        if not data:
            raise socket.error("Socket connection broken")
        data = int(data)

        chunks = []
        bytes_recd = 0
        while bytes_recd < data:
            chunk = self.sock.recv(min(data - bytes_recd, 2048))
            if chunk == b'':
                raise socket.error("Socket connection broken")
            chunks.append(chunk)
            bytes_recd = bytes_recd + len(chunk)
        segments = b''.join(chunks)
        return segments
