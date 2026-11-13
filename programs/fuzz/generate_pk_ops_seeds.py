#!/usr/bin/env python3
"""Seed generator for fuzz_pk_ops.

Wraps real framework key material (PEM/DER: RSA PKCS#1/PKCS#8, EC, public
keys, encrypted PKCS8) with the harness's [op][opts][hash][len16 key]
[len16 payload] framing so every parse path (including encrypted-PBE ones,
which are provably seed-limited today: pkcs12.c and pkcs5.c sit at 0%
despite fuzz_privkey existing for years — DER + PEM framing + PBE OIDs are
a mutation-resistant gate) and every op class is exercised from the start.
"""
import argparse
import base64
import os

DATA_FILES = [
    "server2.key",            # RSA-2048 PKCS#1 PEM
    "server2.key.der",        # RSA DER
    "server2.pub",            # RSA public PEM
    "ec_256_prv.pem",         # EC private SEC1 PEM
    "ec_256_pub.pem",         # EC public PEM
    "ec_382_prv.pem",
    "rsa_pkcs8_pbes2_pbkdf2_1024_3des.der",   # encrypted PKCS#8 PBES2 DER
    "rsa_pkcs8_pbes2_pbkdf2_1024_3des.pem",
    "rsa_pkcs8_pbes2_pbkdf2_2048_3des.sha256.pem",
    "pkcs8-2048-pbes2-sha256.pem",  # encrypted PKCS#8 (PBES2)
    "pkcs8-2048-pbes2-sha1.pem",
]


def frame(op, opts, hash_sel, key, payload):
    return (bytes([op, opts, hash_sel]) +
            len(key).to_bytes(2, "little") + key +
            len(payload).to_bytes(2, "little") + payload)


def load(path):
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except OSError:
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--data-files", required=True,
                    help="framework/data_files directory")
    ap.add_argument("--passwords", default="password,foo", help="csv list")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    passwords = [p.encode() for p in args.passwords.split(",")]
    n = 0

    for name in DATA_FILES:
        key = load(os.path.join(args.data_files, name))
        if key is None:
            continue
        short = name.rsplit(".", 1)[0].replace("-", "_")
        payload = bytes((i * 31 + 7) & 0xFF for i in range(32))
        hash32 = bytes((i * 13 + 3) & 0xFF for i in range(32))

        # parse + sign + verify (private ops)
        seeds = {
            "sign_" + short: frame(0, 0x00, 0, key, hash32),
            "sign_v21_" + short: frame(0, 0x02, 0, key, hash32),
            "verify_" + short: frame(1, 0x00, 0, key, hash32),
            "verifyext_" + short: frame(2, 0x00, 0, key, hash32),
            "decrypt_" + short: frame(3, 0x00, 0, key, payload),
            "encrypt_" + short: frame(4, 0x00, 0, key, payload),
            "write_" + short: frame(5, 0x00, 0, key, payload),
            "rsasign_" + short: frame(6, 0x00, 0, key, hash32),
        }
        # public-parse variants (strip the private flag)
        for k in list(seeds):
            b = bytearray(seeds[k])
            b[0] |= 0x10
            seeds[k.replace("sign_", "pubsign_").replace(
                "decrypt_", "pubdec_").replace(
                "encrypt_", "pubenc_").replace(
                "verifyext_", "pubvext_").replace(
                "write_", "pubwrite_").replace(
                "verify_", "pubver_").replace(
                "rsasign_", "pubrsa_")] = bytes(b)
        # encrypted-parse variants with a password
        for i, pw in enumerate(passwords):
            b = bytearray(seeds["sign_" + short])
            b[1] |= 0x80
            body = bytes(b[6:])
            pwpart = u8(len(pw)) + pw
            seeds["enc%d_" % i + short] = bytes(b[:3]) + \
                len(body).to_bytes(2, "little") + body
            del seeds["enc%d_" % i + short]
            # framed as: header(3) + len16(key) + key + pwpart + payload
            framed = (bytes(b[:6]) + body + pwpart +
                      (32).to_bytes(2, "little") + hash32)
            seeds["enc%d_" % i + short] = framed
        for name2, blob in seeds.items():
            with open(os.path.join(args.out, name2), "wb") as fh:
                fh.write(blob)
            n += 1

    print("wrote %d seeds to %s" % (n, args.out))


def u8(nv):
    return bytes([nv])


if __name__ == "__main__":
    main()
