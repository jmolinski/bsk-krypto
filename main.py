# FLAG1 - aes_encrypted flag, enc_flag1
# option 1 encrypted flag
# "f8dfa195ab5113d18ae72622c5a8c6da:47d1d5efc547ec5b45b57058885540d9d2a8caa50eda15609c17a25f9d:1fd4b01f8e10c8fff20961a4c11f133a"

# https://en.wikipedia.org/wiki/RSA_(cryptosystem)
# FLAG2 = Path("flag_2.txt").read_text().strip()

# ???
# FLAG3 = Path("flag_3.txt").read_text().strip()
#
# RSA_PRIV_KEY = Path("server.pem").read_text()

# https://github.com/Gallopsled/pwntools


from pwn import remote
from flag3_exploit import exploit_flag3, FLAG3_PROBES


def skip_menu(r) -> None:
    r.recvuntil(b"Choice: ")


def get_flag_3():
    r = remote("cryptotask.var.tailcall.net", 30000)

    r.send(b"7\n" * FLAG3_PROBES)

    def get_encrypted_flag3() -> str:
        skip_menu(r)
        return r.recvline(keepends=False).split(b" ")[-1].decode()

    exploit_flag3(get_encrypted_flag3)

    r.close()


def main() -> None:
    get_flag_3()


main()
