#!/usr/bin/env python3
"""Seed generator for fuzz_pk_ops.

Wraps real framework key material (PEM/DER: RSA PKCS#1/PKCS#8, EC, public
keys, encrypted PKCS8) with the harness's
[op][opts][hash][len16 key][key]([pwd_len][pwd])[len16 payload][payload]
framing so every parse path (including encrypted-PBE ones, which are
provably seed-limited today: pkcs12.c and pkcs5.c sit at 0% despite
fuzz_privkey existing for years — DER + PEM framing + PBE OIDs are a
mutation-resistant gate) and every op class is exercised from the start.

PEM key buffers include a terminating NUL: mbedtls_pk_parse_key /
mbedtls_pk_parse_public_key require it to select PEM.
"""
import argparse
import os

DATA_FILES = [
    "server2.key",            # RSA-2048 PKCS#1 PEM
    "server2.key.der",        # RSA DER
    "rsa_pkcs8_2048_public.pem",  # RSA public PEM
    "ec_256_prv.pem",         # EC private SEC1 PEM
    "ec_256_pub.pem",         # EC public PEM
    "ec_384_prv.pem",
    "rsa_pkcs8_pbes2_pbkdf2_1024_3des.der",   # encrypted PKCS#8 PBES2 DER
    "rsa_pkcs8_pbes2_pbkdf2_1024_3des.pem",
    "rsa_pkcs8_pbes2_pbkdf2_2048_3des_sha256.pem",
]

# Password used by framework encrypted PKCS#8 / .key.enc fixtures.
DEFAULT_PASSWORDS = ["PolarSSLTest", "password"]


def as_parse_blob(data):
    """Ensure PEM buffers end with NUL so mbedtls_pk_parse_* selects PEM."""
    if b"-----BEGIN" in data and (not data or data[-1:] != b"\0"):
        return data + b"\0"
    return data


def frame(op, opts, hash_sel, key, payload, password=None):
    key = as_parse_blob(key)
    out = (bytes([op, opts, hash_sel]) +
           len(key).to_bytes(2, "little") + key)
    if password is not None:
        if len(password) > 255:
            raise ValueError("password longer than one length byte")
        out += bytes([len(password)]) + password
    out += len(payload).to_bytes(2, "little") + payload
    return out


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
    ap.add_argument("--passwords", default=",".join(DEFAULT_PASSWORDS),
                    help="csv list")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    passwords = [p.encode() for p in args.passwords.split(",") if p]
    n = 0

    for name in DATA_FILES:
        key = load(os.path.join(args.data_files, name))
        if key is None:
            continue
        short = name.rsplit(".", 1)[0].replace("-", "_")
        payload = bytes((i * 31 + 7) & 0xFF for i in range(32))
        hash32 = bytes((i * 13 + 3) & 0xFF for i in range(32))

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
        # public-parse variants
        for k in list(seeds):
            b = bytearray(seeds[k])
            b[0] |= 0x10
            seeds["pub_" + k] = bytes(b)
        # encrypted-parse variants with a password (opts bit 0x80)
        for i, pw in enumerate(passwords):
            seeds["enc%d_" % i + short] = frame(
                0, 0x80, 0, key, hash32, password=pw)

        for name2, blob in seeds.items():
            with open(os.path.join(args.out, name2), "wb") as fh:
                fh.write(blob)
            n += 1

    print("wrote %d seeds to %s" % (n, args.out))


if __name__ == "__main__":
    main()
