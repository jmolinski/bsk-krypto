FLAG1 = "dupa dupa"

from utils import aes_encrypt, xor


class Simulator:
    def __init__(self, *args, **kwargs):
        self.aes_key = bytearray(b"1234123412341234")
        self.enc_flag1 = aes_encrypt(self.aes_key, FLAG1.encode())

    def getflag(self):
        return self.enc_flag1

    def rekey(self, new_key):
        # xor the provided key with a secret for more security
        new_key = bytes.fromhex(new_key)
        secret = b"0123456789abcdef"
        super_secret_key = xor(new_key, secret)

        for index, byte in enumerate(super_secret_key):
            self.aes_key[index] = byte

    def encrypt(self, msg):
        return aes_encrypt(self.aes_key, bytes.fromhex(msg))
