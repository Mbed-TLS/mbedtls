#!/usr/bin/env python3
"""Seed generator for fuzz_dhm (OSS-Fuzz coverage pipeline pair 10,
mbedtls-dhm).

Frames real DH parameter sets from framework/data_files (dhparams.pem,
dh.998/999/1000.pem non-standard sizes, dh.optlen.*) into the harness layout
[opts][len16 params][params][len16 own_priv][own_priv][len16 peer][peer].
Valid parameter sets are a mutation-resistant gate (PEM framing + the
DER INTEGER encoding of P and G); peer values include in-range and
out-of-range variants so the calc_secret range validation paths run.
"""
import argparse
import glob
import os

PARAM_FILES = ["dhparams.pem", "dh.998.pem", "dh.999.pem", "dh.1000.pem",
               "dh.optlen.pem", "dh.optlen.der"]


def u16(n):
    return n.to_bytes(2, "little")


def frame(opts, params, own_priv, peer):
    # own_priv is ignored by the harness (3.6 generates X internally);
    # kept out of the frame entirely
    return (bytes([opts]) + u16(len(params)) + params +
            u16(len(peer)) + peer)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--data-files", required=True)
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    n = 0
    priv = bytes(range(1, 33))          # 32-byte private exponent
    peer_ok = bytes((i * 5 + 3) & 0xFF for i in range(256))
    peer_small = bytes([1])             # < 2: reject path
    peer_zeros = bytes(256)             # zero value

    for pf in PARAM_FILES:
        p = os.path.join(args.data_files, pf)
        if not os.path.exists(p):
            continue
        params = open(p, "rb").read()
        base = os.path.splitext(pf)[0].replace(".", "_")
        blob = frame(0, params, priv, peer_ok)
        with open(os.path.join(args.out, "valid_" + base), "wb") as fh:
            fh.write(blob)
        n += 1
        blob = frame(0, params, priv, peer_small)
        with open(os.path.join(args.out, "smallpeer_" + base), "wb") as fh:
            fh.write(blob)
        n += 1
        blob = frame(0, params, priv, peer_zeros)
        with open(os.path.join(args.out, "zerospeer_" + base), "wb") as fh:
            fh.write(blob)
        n += 1

    # attacker blob with valid params bytes mutated into a PEM/DER hybrid
    p = os.path.join(args.data_files, "dhparams.pem")
    if os.path.exists(p):
        params = bytearray(open(p, "rb").read())
        params[len(params) // 2] ^= 0xFF
        with open(os.path.join(args.out, "corrupt_params"), "wb") as fh:
            fh.write(frame(0, bytes(params), priv, peer_ok))
        n += 1

    print("wrote %d seeds to %s" % (n, args.out))


if __name__ == "__main__":
    main()
