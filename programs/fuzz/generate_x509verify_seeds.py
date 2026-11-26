#!/usr/bin/env python3
"""Seed generator for fuzz_x509verify.

Frames real certificate chains from framework/data_files into the harness
layout [opts][len16 leaf][leaf][len16 ca][ca][len16 crl][crl].
Chain pairs are a mutation-resistant gate: DER framing plus a signature
over the tbsCertificate cannot be produced by blind mutation, so the verify
(path building, signature check, profile and key-usage policy) side stays
unreachable without real chains. Both valid chains (signature accepted,
path built) and mismatched pairs (verification-failure paths) are emitted.

PEM blobs must include a terminating NUL: mbedtls_x509_crt_parse /
mbedtls_x509_crl_parse only treat a buffer as PEM when buflen includes
that byte.

For the ECDSA pairs issued by the EC CA (the last two PAIRS rows), opts
bit 6 switches the restartable verification to run to completion instead
of stopping after the bounded slice count, so the resume path -- the
restart context carrying state through the chain and returning 0 -- is
covered by the corpus as well.
"""
import argparse
import os

PAIRS = [
    # (leaf, ca) valid server chain
    ("server2.crt", "test-ca.crt"),
    ("server2.crt", "test-ca2.crt"),          # wrong CA: verify-failure path
    ("server2.der", "test-ca.der"),           # DER forms
    ("server1.crt", "test-ca.crt"),
    ("server4.crt", "test-ca.crt"),           # wrong CA: path building fails
    ("cert_example_wildcard.crt", "test-ca.crt"),
    ("server5.crt", "test-ca.crt"),
    # ECDSA-signed chains issued by the EC CA: these actually verify, so the
    # restartable path gets past path building into ECDSA signature slices.
    ("server5.crt", "test-ca2.crt"),
    ("server4.crt", "test-ca2.crt"),
]

CRLS = ["crl.pem", "crl_sha256.pem"]


def as_parse_blob(data):
    """Ensure PEM buffers end with NUL so mbedtls_*_parse selects PEM."""
    if b"-----BEGIN" in data and (not data or data[-1:] != b"\0"):
        return data + b"\0"
    return data


def frame(opts, leafb, cab, crlb=b""):
    leafb = as_parse_blob(leafb)
    cab = as_parse_blob(cab) if cab else cab
    crlb = as_parse_blob(crlb) if crlb else crlb
    return (bytes([opts]) +
            len(leafb).to_bytes(2, "little") + leafb +
            len(cab).to_bytes(2, "little") + cab +
            len(crlb).to_bytes(2, "little") + crlb)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--data-files", required=True)
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    n = 0
    for i, (leaf_name, ca_name) in enumerate(PAIRS):
        p = os.path.join(args.data_files, leaf_name)
        if not os.path.exists(p):
            # A silently skipped row would shrink the corpus with no signal;
            # fail the generation instead so the fixture gets fixed.
            raise SystemExit("data file not found: %s" % p)
        leaf = open(p, "rb").read()
        p = os.path.join(args.data_files, ca_name)
        if not os.path.exists(p):
            raise SystemExit("data file not found: %s" % p)
        ca = open(p, "rb").read()

        # The ECDSA pairs reach signature slicing; on those rows opts bit 6
        # additionally switches the restartable verification to
        # run-to-completion (larger per-call budget, generous slice cap),
        # which needs hundreds of calls on these chains.
        opts_list = (0x00, 0x01, 0x02, 0x10, 0x20, 0x21, 0x22, 0x04, 0x08)
        if i >= 7:
            opts_list = opts_list + (0x60, 0x61, 0x62)
        for opts in opts_list:
            with open(os.path.join(
                    args.out, "chain%d_o%02x" % (i, opts)), "wb") as fh:
                fh.write(frame(opts, leaf, ca))
            n += 1

    for crl_name in CRLS:
        p = os.path.join(args.data_files, crl_name)
        if not os.path.exists(p):
            raise SystemExit("data file not found: %s" % p)
        crl = open(p, "rb").read()
        leaf = None
        for cand in ("server2.crt", "server1.crt"):
            q = os.path.join(args.data_files, cand)
            if os.path.exists(q):
                leaf = open(q, "rb").read()
                break
        if leaf is None:
            raise SystemExit("data file not found: %s" %
                             os.path.join(args.data_files, "server2.crt"))
        ca_path = os.path.join(args.data_files, "test-ca.crt")
        ca = open(ca_path, "rb").read() if os.path.exists(ca_path) else b""
        for opts in (0x10, 0x11):
            with open(os.path.join(args.out, "crl_%s_o%02x" %
                                   (os.path.splitext(crl_name)[0], opts)),
                      "wb") as fh:
                fh.write(frame(opts, leaf, ca, crl))
            n += 1

    print("wrote %d seeds to %s" % (n, args.out))


if __name__ == "__main__":
    main()
