# Autor Jakub Moliński
# Exploity do zadania zaliczeniowego z krypto z BSK*, mimuw 2021


import pwn
from pwn import remote, context
from flag3_exploit import exploit_flag3, FLAG3_PROBES
from utils import rsa_encrypt, aes_decrypt
from utils import aes_encrypt_nonce, xor


def get_remote_connection() -> pwn.remote:
    context.log_level = "error"
    return remote("cryptotask.var.tailcall.net", 30000)


def skip_menu(r) -> None:
    r.recvuntil(b"Choice: ")


def get_flag_2():
    r = get_remote_connection()

    r.send(b"6\n")
    skip_menu(r)
    key = b""
    while not key.endswith(b"-----END PUBLIC KEY-----\n"):
        key += r.recvline(keepends=True)

    token_int = int.from_bytes("flag".encode(), byteorder="big")
    rsa_token = rsa_encrypt(key, token_int)
    r.send(b"5\n")
    skip_menu(r)

    r.send(str(rsa_token).encode() + b"\n")
    r.recvline()
    flag2 = r.recvline().decode().strip().split()[-1]
    r.close()

    print("Captured flag 2:", flag2)


def get_flag_3():
    r = get_remote_connection()

    r.send(b"7\n" * FLAG3_PROBES)

    def get_encrypted_flag3() -> str:
        skip_menu(r)
        return r.recvline(keepends=False).split(b" ")[-1].decode()

    exploit_flag3(get_encrypted_flag3)

    r.close()


def parse_nonce_cipher_tag(bts):
    if isinstance(bts, bytes):
        bts = bts.decode("ascii")
    n, c, _ = bts.split(":")
    n = bytes.fromhex(n)
    c = bytes.fromhex(c)
    return n, c


def preprocess_injected_key(bts):
    secret = b"0123456789abcdef"
    return xor(bts, secret)


def get_flag_1():
    r = get_remote_connection()

    skip_menu(r)
    r.send(b"1\n")
    flag_nonce, flag_ciphertext = parse_nonce_cipher_tag(r.recvline(keepends=False))

    MSG = b"0" * 16

    msgs = {}
    for i in range(0, 16):
        new_key_prefix = b"0" * i

        r.send(b"2\n")
        r.send(preprocess_injected_key(new_key_prefix).hex().encode("ascii") + b"\n")
        skip_menu(r)
        r.recvline()

        r.send(b"3\n")
        r.send(MSG.hex().encode() + b"\n")
        skip_menu(r)
        encrypted = r.recvline(keepends=False).split(b" ")[-1]
        msgs[i] = (new_key_prefix, parse_nonce_cipher_tag(encrypted))

    r.close()

    correct_key_suffix = b""
    for ids in range(15, -1, -1):
        msg = msgs[ids]
        key = msg[0]
        nonce, ciphertext = msg[1]

        for b in range(0, 256):
            b = b.to_bytes(1, "big")
            maybe_key = key + b + correct_key_suffix

            _, cipher_try = aes_encrypt_nonce(maybe_key, MSG, nonce)
            if cipher_try == ciphertext:
                correct_key_suffix = b + correct_key_suffix
                break
        else:
            print("recovery failed")
            break

    flag1 = aes_decrypt(correct_key_suffix, flag_ciphertext, flag_nonce).decode()
    print("Captured flag 1:", flag1)


def main() -> None:
    get_flag_1()
    get_flag_2()
    get_flag_3()


main()
