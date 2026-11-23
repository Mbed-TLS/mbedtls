#!/usr/bin/env python3
"""Seed generator for fuzz_dhm.

Frames real DH parameter sets from framework/data_files (dhparams.pem,
dh.998/999/1000.pem non-standard sizes, dh.optlen.*) into the harness layout
[opts][len16 params][params][len16 peer][peer].
Valid parameter sets are a mutation-resistant gate (PEM framing + the
DER INTEGER encoding of P and G); peer values include in-range and
out-of-range variants so the calc_secret range validation paths run.

PEM parameter buffers include a terminating NUL: mbedtls_dhm_parse_dhm
only treats a buffer as PEM when dhminlen includes that byte.
"""
import argparse
import os

PARAM_FILES = ["dhparams.pem", "dh.998.pem", "dh.999.pem", "dh.1000.pem",
               "dh.optlen.pem", "dh.optlen.der"]


def u16(n):
    return n.to_bytes(2, "little")


def as_parse_blob(data):
    """Ensure PEM buffers end with NUL so mbedtls_dhm_parse_dhm selects PEM."""
    if b"-----BEGIN" in data and (not data or data[-1:] != b"\0"):
        return data + b"\0"
    return data


def frame(opts, params, peer):
    params = as_parse_blob(params)
    return (bytes([opts]) + u16(len(params)) + params +
            u16(len(peer)) + peer)


def seed_base(filename):
    """Unique seed stem: keep extension so .pem/.der do not collide."""
    return filename.replace(".", "_")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--data-files", required=True)
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    n = 0
    peer_ok = bytes((i * 5 + 3) & 0xFF for i in range(256))
    peer_small = bytes([1])             # < 2: reject path
    peer_zeros = bytes(256)             # zero value

    for pf in PARAM_FILES:
        p = os.path.join(args.data_files, pf)
        if not os.path.exists(p):
            continue
        params = open(p, "rb").read()
        base = seed_base(pf)
        for tag, peer in (("valid", peer_ok),
                          ("smallpeer", peer_small),
                          ("zerospeer", peer_zeros)):
            with open(os.path.join(args.out, "%s_%s" % (tag, base)),
                      "wb") as fh:
                fh.write(frame(0, params, peer))
            n += 1

    # attacker blob with valid params bytes mutated into a PEM/DER hybrid
    p = os.path.join(args.data_files, "dhparams.pem")
    if os.path.exists(p):
        params = bytearray(open(p, "rb").read())
        params[len(params) // 2] ^= 0xFF
        with open(os.path.join(args.out, "corrupt_params"), "wb") as fh:
            fh.write(frame(0, bytes(params), peer_ok))
        n += 1

    print("wrote %d seeds to %s" % (n, args.out))


if __name__ == "__main__":
    main()
