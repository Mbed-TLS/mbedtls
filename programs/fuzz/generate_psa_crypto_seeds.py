#!/usr/bin/env python3
"""Structured seed generator for fuzz_psa_crypto (OSS-Fuzz coverage pipeline
pair 1, mbedtls-psa-crypto).

Emits op-script seeds for the stateful PSA API harness, one seed per
algorithm family, so the mutator starts inside the family instead of having
to discover valid PSA attribute combinations through the single-byte
selector encoding (a mutation-resistant gate: attribute selectors and
key-material formats such as DER RSAPrivateKey / raw ECC scalars).

RSA private-key material is taken from an existing framework PEM file
(BEGIN RSA PRIVATE KEY = PKCS#1 DER, exactly the PSA import format), so no
key generation is needed here and the bytes are deterministic.

Usage:
    python3 generate_psa_crypto_seeds.py --out DIR [--rsa-pem FILE]

Byte layout mirrors fuzz_psa_crypto.c exactly (see the harness header).
"""
import argparse
import base64
import os
import re
import sys

K32 = bytes((i * 7 + 11) & 0xFF for i in range(32))
K16 = bytes((i * 13 + 5) & 0xFF for i in range(16))
K8 = bytes((i * 29 + 3) & 0xFF for i in range(8))
PT = bytes((i * 31 + 7) & 0xFF for i in range(64))

# key type selectors (key_type_from_sel)
T_RAW, T_HMAC, T_AES, T_ARIA, T_CAM, T_CHACHA, T_DES = 0, 1, 2, 3, 4, 5, 6
T_RSA_PUB, T_RSA_PRIV, T_EC_P256, T_EC_K1, T_EC_MONT, T_DH, T_PASSWD = \
    7, 8, 9, 10, 11, 12, 13

# op codes (LLVMFuzzerTestOneInput switch)
O_IMP, O_GEN, O_HASH, O_MAC, O_CIPH, O_AEAD = 0, 1, 2, 3, 4, 5
O_SIGN_H, O_VER_H, O_SIGN_M, O_VER_M, O_AENC, O_ADEC = 6, 7, 8, 9, 10, 11
O_AGR, O_KDF, O_EXP, O_EXPP, O_COPY, O_PURGE = 12, 13, 14, 15, 16, 17
O_IMPP, O_GENP, O_RAND, O_OPEN = 18, 19, 20, 21


def imp(typesel, keybytes, algsel, algbytes, persistent=None):
    """import: type, len(2 LE), bytes, algsel, alg bytes [, id]"""
    kb = list(keybytes)
    out = [O_IMPP if persistent is not None else O_IMP, typesel,
           len(kb) & 0xFF, (len(kb) >> 8) & 0xFF] + kb + [algsel] + algbytes
    if persistent is not None:
        out.append(persistent)
    return out


def gen(typesel, bitsel, algsel, algbytes, persistent=None):
    """generate: type, bits, algsel, alg bytes [, id]"""
    out = [O_GENP if persistent is not None else O_GEN, typesel, bitsel,
           algsel] + algbytes
    if persistent is not None:
        out.append(persistent)
    return out


def script(*ops):
    return bytes([len(ops)] + sum(([int(b) for b in op] for op in ops), []))


def cap(bits):
    """KDF capacity as 2-byte LE (harness: (get16 & 0xFFF) * 8 + 1)."""
    n = max(0, (bits - 1) // 8)
    return [n & 0xFF, (n >> 8) & 0xFF]


def seeds(rsa_der):
    out = {}

    out["hash_sha256_clone"] = script(
        [O_HASH, 5, 1, 32] + list(K32))                       # SHA-256 + clone
    out["hash_sha3_512_verify"] = script(
        [O_HASH, 9, 2, 32] + list(K32) + list(K32))           # SHA3-512 + verify
    out["hash_ripemd160"] = script(
        [O_HASH, 6, 0, 16] + list(K16))                       # RIPEMD-160

    # HMAC-SHA256: import 32-byte HMAC key, compute + multipart sign
    out["hmac_sha256"] = script(
        imp(T_HMAC, K32, 1, [1, 5, 1]),                       # mac: HMAC(SHA256)
        [O_MAC, 0, 5, 1, 32] + list(K32),
        [O_MAC, 0, 5, 2, 16] + list(K16))
    # CMAC-AES: import AES key with CMAC policy, multipart sign + wrong verify
    out["cmac_aes"] = script(
        imp(T_AES, K16, 1, [1, 0, 0]),                        # mac: CMAC
        [O_MAC, 0, 0, 2, 16] + list(K16),
        [O_MAC, 0, 0, 6, 16] + list(K16) + [16] + list(K16))

    # AES-CBC-PKCS7 one-shot round trip
    out["aes_cbc_pkcs7"] = script(
        imp(T_AES, K16, 1, [5]),                              # cipher CBC_PKCS7
        [O_CIPH, 0, 5, 1, 32] + list(PT) + [16] + list(K16))
    # AES-CTR multipart (generate_iv)
    out["aes_ctr_multipart"] = script(
        imp(T_AES, K16, 1, [1]),
        [O_CIPH, 0, 1, 2, 64] + list(PT))
    # AES-CFB multipart decrypt with set_iv
    out["aes_cfb_decrypt_mp"] = script(
        imp(T_AES, K16, 1, [2]),
        [O_CIPH, 0, 2, 6, 16] + list(K16) + [16] + list(K16))
    # DES-CBC-PKCS7 (64/128/192-bit DES through PSA)
    out["des_cbc"] = script(
        gen(T_DES, 2, 1, [5]),
        [O_CIPH, 0, 5, 1, 8] + list(K8) + [8] + list(K8))

    # AES-GCM one-shot round trip + multipart (set_nonce)
    out["aes_gcm"] = script(
        imp(T_AES, K16, 4, [0, 0]),                           # aead GCM default tag
        [O_AEAD, 0, 0, 3, 12] + list(K16[:12]) + [8] + list(K8[:8]) +
        [32] + list(PT))
    # AES-CCM shortened tag
    out["aes_ccm_shorttag"] = script(
        imp(T_AES, K16, 4, [1, 8]),                           # CCM tag len 6
        [O_AEAD, 1, 0, 1, 12] + list(K16[:12]) + [4] + list(K8[:4]) +
        [16] + list(K16))
    # ChaCha20-Poly1305
    out["chachapoly"] = script(
        imp(T_CHACHA, K32, 4, [2, 0]),                        # CHACHA20_POLY1305
        [O_AEAD, 2, 0, 3, 12] + list(K16[:12]) + [4] + list(K8[:4]) +
        [24] + list(PT[:24]))
    # ARIA-GCM / CAMELLIA-CCM
    out["aria_gcm"] = script(
        gen(T_ARIA, 0, 2, [0, 0]),
        [O_AEAD, 0, 0, 3, 12] + list(K16[:12]) + [4] + list(K8[:4]) +
        [16] + list(K16))
    out["camellia_ccm"] = script(
        gen(T_CAM, 0, 2, [1, 0]),
        [O_AEAD, 1, 0, 3, 12] + list(K16[:12]) + [4] + list(K8[:4]) +
        [16] + list(K16))


    if rsa_der is not None:
        # RSA-2048 PKCS1v15-SHA256 sign + verify + verify-bad
        out["rsa_pkcs1v15_sign"] = script(
            imp(T_RSA_PRIV, rsa_der, 2, [0, 5]),              # sig PKCS1v15 SHA256
            [O_SIGN_H, 0, 0, 5, 32] + list(K32),
            [O_VER_H, 0, 0, 5, 32] + list(K32) + [16] + list(K16[:16]))
        # RSA-PSS sign/verify-message
        out["rsa_pss_message"] = script(
            imp(T_RSA_PRIV, rsa_der, 2, [2, 5]),              # PSS(SHA256)
            [O_SIGN_M, 0, 2, 5, 48] + list(PT[:48]))
        # RSA-OAEP-SHA256 encrypt + decrypt(junk ciphertext -> padding path)
        out["rsa_oaep"] = script(
            imp(T_RSA_PRIV, rsa_der, 5, [1, 5]),              # OAEP(SHA256)
            [O_AENC, 0, 1, 5, 32] + list(K32) + [0],
            [O_ADEC, 0, 1, 5, 128] + list(PT[:128]) + [0])

    # ECDSA P-256: import raw scalar, sign + verify(junk sig)
    out["ecdsa_p256"] = script(
        imp(T_EC_P256, K32, 2, [4, 5]),                       # ECDSA(SHA256)
        [O_SIGN_H, 0, 4, 5, 32] + list(K32),
        [O_VER_H, 0, 4, 5, 32] + list(K32) + [64] + list(PT[:64]))
    # deterministic ECDSA P-384 generated
    out["ecdsa_det_p384"] = script(
        gen(T_EC_P256, 3, 1, [5, 3]),                         # DET-ECDSA(SHA384)
        [O_SIGN_H, 0, 5, 3, 48] + list(PT[:48]))

    # X25519 key agreement (everest path in the usepsa build)
    out["x25519_agreement"] = script(
        gen(T_EC_MONT, 1, 3, [0]),                            # policy ECDH
        [O_AGR, 0, 32] + list(K32))
    # P-256 agreement with an attacker peer point (validation paths)
    out["p256_agreement"] = script(
        gen(T_EC_P256, 1, 3, [0]),
        [O_AGR, 0, 65] + [0x04] + list(K32) + list(K32))
    # FFDH RFC7919 2048-bit
    out["ffdh_2048"] = script(
        gen(T_DH, 0, 3, [1]),                                 # policy FFDH
        [O_AGR, 1, 255] + list(PT * 3) + list(PT[:63]))

    # HKDF-SHA256: secret/salt/info bytes + output bytes + output key
    out["hkdf_sha256"] = script(
        imp(T_HMAC, K32, 3, [0, 5]),                          # kdf HKDF(SHA256)
        [O_KDF, 0, 5, 3] + cap(512) +
        [0, 32] + list(K32) +                                 # SECRET bytes
        [2, 8] + list(K8[:8]) +                               # SALT
        [4, 8] + list(K8[8:]) +                               # INFO
        [2])                                                  # 2 outputs
    # PBKDF2-HMAC-SHA256 from a PASSWORD key
    out["pbkdf2_password"] = script(
        imp(T_PASSWD, K8[:8], 3, [5, 5]),                     # PBKDF2-HMAC(SHA256)
        [O_KDF, 5, 5, 1] + cap(128) +
        [1, 8] + list(K8[:8]) +
        [1])
    # TLS12-PRF with SECRET as key input + LABEL
    out["tls12_prf"] = script(
        imp(T_HMAC, K32, 3, [3, 5]),
        [O_KDF, 3, 5, 2] + cap(256) +
        [0x40, 0] +                                           # SECRET via key
        [3, 4] + list(K8[:4]) +
        [1])
    # HKDF-EXTRACT with OTHER_SECRET as key input
    out["hkdf_extract_other_secret"] = script(
        imp(T_HMAC, K32, 3, [1, 5]),
        [O_KDF, 1, 5, 2] + cap(128) +
        [0, 16] + list(K16) +
        [0x46, 0] +                                           # OTHER_SECRET key
        [1])

    # persistent key import/open + generated persistent key
    out["persistent_import_open"] = script(
        imp(T_AES, K16, 1, [1], persistent=3),
        [O_OPEN, 3])
    out["persistent_generate_open"] = script(
        gen(T_AES, 0, 1, [1], persistent=5),
        [O_OPEN, 5])

    # copy + purge
    out["copy_purge"] = script(
        imp(T_AES, K16, 1, [1]),
        [O_COPY, 0],
        [O_PURGE, 0])

    # generate_random
    out["generate_random"] = script([O_RAND, 64])

    return out



def load_rsa_der(path):
    """Extract PKCS#1 DER from a BEGIN RSA PRIVATE KEY PEM file."""
    text = open(path, "r").read()
    match = re.search(r"-----BEGIN RSA PRIVATE KEY-----"
                      r"(.*?)-+END RSA PRIVATE KEY-", text, re.S)
    if match is None:
        return None
    return base64.b64decode("".join(match.group(1).split()))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--rsa-pem", default=None,
                    help="PEM file with BEGIN RSA PRIVATE KEY (PKCS#1)")
    args = ap.parse_args()

    rsa_der = load_rsa_der(args.rsa_pem) if args.rsa_pem else None
    if args.rsa_pem and rsa_der is None:
        print("warning: no RSA PRIVATE KEY block found in %s" % args.rsa_pem,
              file=sys.stderr)

    os.makedirs(args.out, exist_ok=True)
    all_seeds = seeds(rsa_der)
    for name, blob in all_seeds.items():
        with open(os.path.join(args.out, name), "wb") as fh:
            fh.write(blob)
    print("wrote %d seeds to %s" % (len(all_seeds), args.out))


if __name__ == "__main__":
    main()
