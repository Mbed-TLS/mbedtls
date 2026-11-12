#!/usr/bin/env python3
"""Seed generator for fuzz_pkcs12 (OSS-Fuzz coverage pipeline pair 8,
mbedtls-pkcs12).

Emits handcrafted, structurally-valid PBES1/PBES2 DER parameter structures
(salt OCTET STRINGs, iteration INTEGERs, PRF/cipher AlgorithmIdentifiers)
plus PBKDF2 seeds — the mutation-resistant gate that keeps pkcs12.c and
pkcs5.c at 0%: blind mutation cannot produce well-formed DER parameter
sequences. Layout mirrors fuzz_pkcs12.c exactly:
[op][md][mode][iter][len16 pwd][pwd][len16 salt][salt][len16 params]
[params][len16 data][data]
"""
import argparse
import os

PWD = b"password"
SALT8 = bytes((i * 17 + 3) & 0xFF for i in range(8))
SALT16 = bytes((i * 7 + 11) & 0xFF for i in range(16))
DATA = bytes((i * 31 + 9) & 0xFF for i in range(64))
IV16 = bytes((i * 23 + 1) & 0xFF for i in range(16))

OID_PBKDF2 = bytes.fromhex("060b2a864886f70d01050c")      # 1.2.840.113549.1.5.12
OID_AES128CBC = bytes.fromhex("06096086480165030401")      # 2.16...aes128-cbc (trunc?)
OID_AES256CBC = bytes.fromhex("0609608648016503042a")      # aes256-cbc
OID_HMAC_SHA1 = bytes.fromhex("06052b0e03021a")            # 1.2.840.113549.2.7
OID_HMAC_SHA256 = bytes.fromhex("0609608648016503040201")  # 2.16...sha256


def u8(n):
    return bytes([n])


def u16(n):
    return n.to_bytes(2, "little")


def u16b(n):
    return n.to_bytes(2, "big")


def u32b(n):
    return n.to_bytes(4, "big")


def seq(*parts):
    body = b"".join(parts)
    return b"\x30" + (u8(len(body)) if len(body) < 128
                      else b"\x81" + u8(len(body))) + body


def octet(b):
    return b"\x04" + (u8(len(b)) if len(b) < 128 else b"\x81" + u8(len(b))) + b


def integer(n):
    out = b""
    while n:
        out = bytes([n & 0xFF]) + out
        n >>= 8
    return b"\x02" + u8(len(out) or 1) + (out or b"\x00")


def algid(oid, params):
    return seq(oid, params)


def frame(op, md, mode, iters, pwd, salt, params, data):
    return (bytes([op, md, mode, iters]) + u16(len(pwd)) + pwd +
            u16(len(salt)) + salt + u16(len(params)) + params +
            u16(len(data)) + data)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    seeds = {}

    # PBKDF2-params: SEQUENCE { salt, iterations } (10 iterations)
    p12_salt_int = seq(octet(SALT8), integer(10))

    # PKCS#12 KDF seeds (direct derivation, no ASN.1)
    seeds["deriv_key_sha256"] = frame(0, 0, 0, 8, PWD, SALT8, b"", DATA)
    seeds["deriv_iv_sha1"] = frame(0, 4, 0, 8, PWD, SALT16, b"", DATA)

    # PBES1 (PKCS#12 PBE): params = SEQUENCE { salt, iterations }
    pbes1 = seq(octet(SALT8), integer(1000))
    seeds["pbes1_aes128_enc"] = frame(1, 0, 1, 15, PWD, b"", pbes1, DATA)
    seeds["pbes1_aes256_dec"] = frame(2, 1, 0, 15, PWD, b"", pbes1, DATA)
    seeds["pbes1_3des_dec"] = frame(2, 4, 0, 15, PWD, b"", pbes1, DATA)
    seeds["pbes1_des_enc"] = frame(1, 4, 1, 15, PWD, b"", pbes1, DATA)

    # PBES2: algid(PBKDF2, params) + algid(aes-cbc, IV)
    pbkdf2_params_sha1 = seq(octet(SALT8), integer(10))
    pbkdf2_params_sha256 = seq(octet(SALT16), integer(1000),
                               algid(OID_HMAC_SHA256, b""))
    pbkdf2_algid_sha1 = seq(OID_PBKDF2, pbkdf2_params_sha1)
    pbkdf2_algid_sha256 = seq(OID_PBKDF2, pbkdf2_params_sha256)
    pbes2_sha1_aes128 = seq(pbkdf2_algid_sha1, algid(OID_AES128CBC, octet(IV16)))
    pbes2_sha256_aes256 = seq(pbkdf2_algid_sha256,
                              algid(OID_AES256CBC, octet(IV16)))
    seeds["pbes2_sha1_aes128_enc"] = frame(3, 0, 1, 15, PWD, b"",
                                           pbes2_sha1_aes128, DATA)
    seeds["pbes2_sha256_aes256_dec"] = frame(4, 0, 0, 15, PWD, b"",
                                             pbes2_sha256_aes256, DATA)
    seeds["pbes2_sha256_aes256_enc"] = frame(3, 0, 1, 15, PWD, b"",
                                             pbes2_sha256_aes256, DATA)

    # PBKDF2 direct (iteration matrix)
    seeds["pbkdf2_1_sha256"] = frame(5, 0, 0, 0, PWD, SALT16, b"", DATA)
    seeds["pbkdf2_1009_sha512"] = frame(5, 1, 0, 63, PWD, SALT16, b"", DATA)
    seeds["pbkdf2_129_md5"] = frame(5, 5, 0, 8, PWD, SALT8, b"", DATA)

    # corrupt-params path (flip a byte inside the DER sequence)
    bad = bytearray(pbes1)
    bad[len(bad) // 2] ^= 0xFF
    seeds["pbes1_corrupt_params"] = frame(2, 4, 0, 15, PWD, b"", bytes(bad),
                                          DATA)

    n = 0
    for name, blob in seeds.items():
        with open(os.path.join(args.out, name), "wb") as fh:
            fh.write(blob)
        n += 1
    print("wrote %d seeds to %s" % (n, args.out))


if __name__ == "__main__":
    main()
