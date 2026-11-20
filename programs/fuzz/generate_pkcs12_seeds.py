#!/usr/bin/env python3
"""Seed generator for fuzz_pkcs12.

Emits handcrafted, structurally-valid PBES1/PBES2 DER parameter structures
(salt OCTET STRINGs, iteration INTEGERs, PRF/cipher AlgorithmIdentifiers)
plus PBKDF2 seeds — the mutation-resistant gate that keeps pkcs12.c and
pkcs5.c at 0%: blind mutation cannot produce well-formed DER parameter
sequences. Layout mirrors fuzz_pkcs12.c exactly:
[op][md][mode][iter][len16 pwd][pwd][len16 salt][salt][len16 params]
[params][len16 data][data]

The params blob is SEQUENCE *contents* (no outer 0x30 header): the harness
sets asn1_buf.tag = SEQUENCE and points .p at this blob, matching how
pkcs12_parse_pbe_params / pkcs5_pbes2_ext consume mbedtls_asn1_buf.
"""
import argparse
import os

PWD = b"password"
SALT8 = bytes((i * 17 + 3) & 0xFF for i in range(8))
SALT16 = bytes((i * 7 + 11) & 0xFF for i in range(16))
DATA = bytes((i * 31 + 9) & 0xFF for i in range(64))
IV16 = bytes((i * 23 + 1) & 0xFF for i in range(16))

# ASN.1 OBJECT IDENTIFIER TLVs (tag 0x06 + length + value)
OID_PBKDF2 = bytes.fromhex("06092a864886f70d01050c")       # 1.2.840.113549.1.5.12
OID_AES128CBC = bytes.fromhex("0609608648016503040102")    # 2.16.840.1.101.3.4.1.2
OID_AES256CBC = bytes.fromhex("060960864801650304012a")    # 2.16.840.1.101.3.4.1.42
OID_HMAC_SHA1 = bytes.fromhex("06082a864886f70d0207")      # 1.2.840.113549.2.7
OID_HMAC_SHA256 = bytes.fromhex("06082a864886f70d0209")    # 1.2.840.113549.2.9


def u8(n):
    return bytes([n])


def u16(n):
    return n.to_bytes(2, "little")


def seq(*parts):
    """Full SEQUENCE TLV."""
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
    """AlgorithmIdentifier SEQUENCE TLV."""
    return seq(oid, params)


def algid_null(oid):
    """AlgorithmIdentifier with NULL parameters (for PRF)."""
    return seq(oid, b"\x05\x00")


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

    # PKCS#12 KDF seeds (direct derivation, no ASN.1)
    seeds["deriv_key_sha256"] = frame(0, 0, 0, 8, PWD, SALT8, b"", DATA)
    seeds["deriv_iv_sha1"] = frame(0, 4, 1, 8, PWD, SALT16, b"", DATA)

    # PBES1 (PKCS#12 PBE): SEQUENCE contents { salt, iterations }
    pbes1 = octet(SALT8) + integer(1000)
    seeds["pbes1_aes128_enc"] = frame(1, 0, 1, 15, PWD, b"", pbes1, DATA)
    seeds["pbes1_aes256_dec"] = frame(2, 1, 0, 15, PWD, b"", pbes1, DATA)
    seeds["pbes1_3des_dec"] = frame(2, 4, 0, 15, PWD, b"", pbes1, DATA)
    seeds["pbes1_des_enc"] = frame(1, 4, 1, 15, PWD, b"", pbes1, DATA)

    # PBES2: outer SEQUENCE contents = algid(PBKDF2) || algid(aes-cbc, IV)
    # Nested AlgorithmIdentifier / PBKDF2-params keep their own SEQUENCE TLVs.
    pbkdf2_params_sha1 = seq(octet(SALT8), integer(10))
    pbkdf2_params_sha256 = seq(octet(SALT16), integer(1000),
                               algid_null(OID_HMAC_SHA256))
    pbkdf2_params_hmac_sha1 = seq(octet(SALT8), integer(10),
                                  algid_null(OID_HMAC_SHA1))
    pbkdf2_algid_sha1 = algid(OID_PBKDF2, pbkdf2_params_sha1)
    pbkdf2_algid_sha256 = algid(OID_PBKDF2, pbkdf2_params_sha256)
    pbkdf2_algid_hmac_sha1 = algid(OID_PBKDF2, pbkdf2_params_hmac_sha1)
    pbes2_sha1_aes128 = (pbkdf2_algid_sha1 +
                         algid(OID_AES128CBC, octet(IV16)))
    pbes2_sha256_aes256 = (pbkdf2_algid_sha256 +
                           algid(OID_AES256CBC, octet(IV16)))
    pbes2_hmac_sha1_aes128 = (pbkdf2_algid_hmac_sha1 +
                              algid(OID_AES128CBC, octet(IV16)))
    seeds["pbes2_sha1_aes128_enc"] = frame(3, 0, 1, 15, PWD, b"",
                                           pbes2_sha1_aes128, DATA)
    seeds["pbes2_sha256_aes256_dec"] = frame(4, 0, 0, 15, PWD, b"",
                                             pbes2_sha256_aes256, DATA)
    seeds["pbes2_sha256_aes256_enc"] = frame(3, 0, 1, 15, PWD, b"",
                                             pbes2_sha256_aes256, DATA)
    seeds["pbes2_hmac_sha1_aes128_enc"] = frame(3, 0, 1, 15, PWD, b"",
                                                pbes2_hmac_sha1_aes128, DATA)

    # PBKDF2 direct (iteration matrix)
    seeds["pbkdf2_1_sha256"] = frame(5, 0, 0, 0, PWD, SALT16, b"", DATA)
    seeds["pbkdf2_1009_sha512"] = frame(5, 1, 0, 63, PWD, SALT16, b"", DATA)
    seeds["pbkdf2_129_md5"] = frame(5, 5, 0, 8, PWD, SALT8, b"", DATA)

    # corrupt-params path (flip a byte inside the SEQUENCE contents)
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
