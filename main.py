# Autor Jakub Moliński
# Exploity do zadania zaliczeniowego z krypto z BSK*, mimuw 2021


import pwn
from utils import rsa_encrypt, aes_decrypt, aes_encrypt_nonce, xor
import string
from os import urandom
from collections import Counter, defaultdict

# ---------------------------- common ----------------------------------


def get_remote_connection() -> pwn.remote:
    pwn.context.log_level = "error"
    return pwn.remote("cryptotask.var.tailcall.net", 30000)


def skip_menu(r) -> None:
    r.recvuntil(b"Choice: ")


# ---------------------------- FLAG 1 ----------------------------------


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


# ---------------------------- FLAG 2 ----------------------------------


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

    print("Captured flag 2:", flag2)


# ---------------------------- FLAG 3 ----------------------------------

CHARSET = string.ascii_letters + string.digits + "{}_"
FLAG3_PROBES = 60000


def exploit_flag3(get_encrypted_flag) -> None:
    f3s = [get_encrypted_flag() for _ in range(FLAG3_PROBES)]

    nth_char_positions = defaultdict(list)
    for f in f3s:
        for i, c in enumerate(f):
            nth_char_positions[i].append(CHARSET.index(c))

    nth_char_least_common = {
        k: get_least_common_keys(Counter(v), 4) for k, v in nth_char_positions.items()
    }

    least_likely_by_char = get_least_likely_encrypted_values_for_chars()
    char_by_least_likely = {v: k for k, v in least_likely_by_char.items()}

    flag3 = "".join(
        char_by_least_likely[nth_char_least_common[k]]
        for k in sorted(nth_char_least_common.keys())
    )
    print("Captured flag 3:", flag3)


def get_least_common_keys(c: Counter[int, int], n: int) -> tuple[int, ...]:
    return tuple(sorted(k for (k, _) in c.most_common()[-n:]))


def get_least_likely_encrypted_values_for_chars():
    keys = [urandom(1)[0] % len(CHARSET) for _ in range(200000)]

    least_common_enc_for_char = {}
    for char in CHARSET:
        char_idx = CHARSET.index(char)
        c = Counter((char_idx + key) % len(CHARSET) for key in keys)
        least_common_enc_for_char[char] = get_least_common_keys(c, 4)

    return least_common_enc_for_char


def get_flag_3():
    r = get_remote_connection()

    r.send(b"7\n" * FLAG3_PROBES)

    def get_encrypted_flag3() -> str:
        skip_menu(r)
        return r.recvline(keepends=False).split(b" ")[-1].decode()

    exploit_flag3(get_encrypted_flag3)


# ---------------------------- main ----------------------------------


def main() -> None:
    get_flag_1()
    get_flag_2()
    get_flag_3()


main()
