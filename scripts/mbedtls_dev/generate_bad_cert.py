#!/usr/bin/env python3
"""Generate bad certificate file
"""

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
#


# For testing purpose, we need some wrong certificate file as input. And change the binary/base64
# input might be fail under certain circumstances.

# `*-badsign.crt` won't be generated as expected with origin command at some cases.

# - Old command: `{ head -n-2 $<; tail -n-2 $< | sed -e '1s/0\(=*\)$$/_\1/' \
#                   -e '1s/[^_=]\(=*\)$$/0\1/' -e '1s/_/1/'; }`
# - The context that can not be generated as expected
# ```
# -----BEGIN CERTIFICATE-----
# MIIBszCCATqgAwIBAgIBTTAKBggqhkjOPQQDAjBLMQswCQYDVQQGEwJOTDERMA8G
# A1UECgwIUG9sYXJTU0wxKTAnBgNVBAMMIFBvbGFyU1NMIFRlc3QgSW50ZXJtZWRp
# YXRlIEVDIENBMB4XDTIzMDYxMjA5MDUyMFoXDTMzMDYxMjA5MDUyMFowSjELMAkG
# A1UEBhMCVUsxETAPBgNVBAoMCG1iZWQgVExTMSgwJgYDVQQDDB9tYmVkIFRMUyBU
# ZXN0IGludGVybWVkaWF0ZSBDQSAzMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
# 732fWHLNPMPsP1U1ibXvb55erlEVMlpXBGsj+KYwVqU1XCmW9Z9hhP7X/5js/DX9
# 2J/utoHyjUtVpQOzdTrbsaMQMA4wDAYDVR0TBAUwAwEB/zAKBggqhkjOPQQDAgNn
# ADBkAjArIP+ae7xHpa20iO82VItiDrlmJqwbWmn34wG84YXnlkRDecsHOMmFxQBc
# dYs58MkCMFqlvEzX0LxPYhGoUPel0PZXWo8YNPdnnPI1VPrf+bnJEl7Wyp2KtCE5
# oV+VwkEu7w==
# -----END CERTIFICATE-----
# ```

import argparse
import sys
# type: ignore #pylint: disable=import-error
from asn1crypto import pem, x509, core


def generate_badsign(**kwargs):
    """Generate badsign certificate
    """
    def output_badsign(f_out_write):
        seq = iter(range(2**32))
        for fname in kwargs.get('certificate-files'):
            with open(fname, 'rb') as f:
                pem_data = f.read()

            for type_name, headers, der_bytes in pem.unarmor(pem_data, multiple=True):
                assert type_name == 'CERTIFICATE'
                assert not headers
                cert_obj = x509.Certificate.load(der_bytes)
                if next(seq) == 0:
                    signature = cert_obj.signature
                    byte = signature[-1] ^ 3
                    signature = signature[:-1] + byte.to_bytes(1, 'little')
                    cert_obj['signature_value'] = core.OctetBitString(
                        signature)
                f_out_write(pem.armor('CERTIFICATE', cert_obj.dump()))
    output = kwargs.get('output')
    if output is None:
        return output_badsign(sys.stdout.buffer.write)
    with open(output, 'wb') as f:
        return output_badsign(f.write)


def build_badsign(subparsers):
    """Build argument parser"""
    badsign_parser = subparsers.add_parser("badsign")
    badsign_parser.description = "generate badsign certificate"
    badsign_parser.add_argument('certificate-files', type=str, nargs='+',
                                help='certificate files')
    badsign_parser.add_argument('--output', type=str, default=None)


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(title="sub-commands", dest="command")

    build_badsign(subparsers)
    args = parser.parse_args()
    return globals()['generate_{}'.format(args.command)](**vars(args))


if __name__ == '__main__':
    main()
