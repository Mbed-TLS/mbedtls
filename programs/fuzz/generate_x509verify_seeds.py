#!/usr/bin/env python3
"""Seed generator for fuzz_x509verify.

Frames real certificate chains from framework/data_files into the harness
layout [opts][hash][len16 leaf][leaf][len16 ca][ca][len16 crl][crl].
Chain pairs are a mutation-resistant gate: DER framing plus a signature
over the tbsCertificate cannot be produced by blind mutation, so the verify
(path building, signature check, profile and key-usage policy) side stays
unreachable without real chains. Both valid chains (signature accepted,
path built) and mismatched pairs (verification-failure paths) are emitted.
"""
import argparse
import os

PAIRS = [
    # (leaf, ca) valid server chain
    ("server2.crt", "test-ca.crt"),
    ("server2.crt", "test-ca2.crt"),          # wrong CA: verify-failure path
    ("server2.der", "test-ca.crt.der"),       # DER forms
    ("server1.crt", "test-ca.crt"),
    ("server4.crt", "test-ca.crt"),           # wrong key usage certs
    ("cert_example_crt.pem", "test-ca.crt"),
    ("server5.crt", "test-ca.crt"),
]

CRLS = ["crl.pem", "crl_sha256.pem", "crl-der.der"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--data-files", required=True)
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    n = 0
    for i, (leaf_name, ca_name) in enumerate(PAIRS):
        leaf = None
        ca = None
        for cand in (leaf_name,):
            p = os.path.join(args.data_files, cand)
            if os.path.exists(p):
                leaf = open(p, "rb").read()
        p = os.path.join(args.data_files, ca_name)
        if os.path.exists(p):
            ca = open(p, "rb").read()
        if leaf is None:
            continue
        ca = ca or b""

        def frame(opts, leafb, cab, crlb=b""):
            out = (bytes([opts, 0]) +
                   len(leafb).to_bytes(2, "little") + leafb +
                   len(cab).to_bytes(2, "little") + cab +
                   len(crlb).to_bytes(2, "little") + crlb)
            return out

        for opts in (0x00, 0x01, 0x02, 0x10, 0x20, 0x21, 0x22, 0x04, 0x08):
            with open(os.path.join(
                    args.out, "chain%d_o%02x" % (i, opts)), "wb") as fh:
                fh.write(frame(opts, leaf, ca))
            n += 1

    for crl_name in CRLS:
        p = os.path.join(args.data_files, crl_name)
        if not os.path.exists(p):
            continue
        crl = open(p, "rb").read()
        leaf = None
        for cand in ("server2.crt", "server1.crt"):
            q = os.path.join(args.data_files, cand)
            if os.path.exists(q):
                leaf = open(q, "rb").read()
                break
        if leaf is None:
            continue
        ca = open(os.path.join(args.data_files, "test-ca.crt"), "rb").read() \
            if os.path.exists(os.path.join(args.data_files,
                                           "test-ca.crt")) else b""
        for opts in (0x10, 0x11):
            with open(os.path.join(args.out, "crl_%s_o%02x" %
                                   (os.path.splitext(crl_name)[0], opts)),
                      "wb") as fh:
                fh.write(frame(opts, leaf, ca, crl))
            n += 1

    print("wrote %d seeds to %s" % (n, args.out))


if __name__ == "__main__":
    main()
