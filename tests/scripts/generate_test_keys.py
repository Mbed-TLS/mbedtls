#!/usr/bin/env python3

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

"""Module generating EC and RSA keys to be used in test_suite_pk instead of
generating the required key at run time. This helps speeding up testing."""

import os
import sys
# pylint: disable=wrong-import-position
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__)) + "/"
sys.path.append(SCRIPT_DIR + "../../scripts/")
from mbedtls_dev.asymmetric_key_data import ASYMMETRIC_KEY_DATA

OUTPUT_HEADER_FILE = SCRIPT_DIR + "../src/test_keys.h"
BYTES_PER_LINE = 12

KEYS = {
    # RSA keys
    'test_rsa_1024': ['PSA_KEY_TYPE_RSA_KEY_PAIR', 1024],
    'test_rsa_1026': ['PSA_KEY_TYPE_RSA_KEY_PAIR', 1026],
    'test_rsa_1028': ['PSA_KEY_TYPE_RSA_KEY_PAIR', 1028],
    'test_rsa_1030': ['PSA_KEY_TYPE_RSA_KEY_PAIR', 1030],
    'test_rsa_2048': ['PSA_KEY_TYPE_RSA_KEY_PAIR', 2048],
    'test_rsa_4096': ['PSA_KEY_TYPE_RSA_KEY_PAIR', 4096],
    # EC keys
    'test_ec_secp192r1_priv': ['PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1)', 192],
    'test_ec_secp192r1_pub': ['PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1)', 192],
    'test_ec_secp224r1_priv': ['PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1)', 224],
    'test_ec_secp224r1_pub': ['PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1)', 224],
    'test_ec_secp256r1_priv': ['PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1)', 256],
    'test_ec_secp256r1_pub': ['PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1)', 256],
    'test_ec_secp384r1_priv': ['PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1)', 384],
    'test_ec_secp384r1_pub': ['PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1)', 384],
    'test_ec_secp521r1_priv': ['PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1)', 521],
    'test_ec_secp521r1_pub': ['PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1)', 521],
    'test_ec_bp256r1_priv': ['PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_BRAINPOOL_P_R1)', 256],
    'test_ec_bp256r1_pub': ['PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_BRAINPOOL_P_R1)', 256],
    'test_ec_bp384r1_priv': ['PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_BRAINPOOL_P_R1)', 384],
    'test_ec_bp384r1_pub': ['PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_BRAINPOOL_P_R1)', 384],
    'test_ec_bp512r1_priv': ['PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_BRAINPOOL_P_R1)', 512],
    'test_ec_bp512r1_pub': ['PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_BRAINPOOL_P_R1)', 512],
    'test_ec_secp192k1_priv': ['PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_K1)', 192],
    'test_ec_secp192k1_pub': ['PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_K1)', 192],
    'test_ec_secp256k1_priv': ['PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_K1)', 256],
    'test_ec_secp256k1_pub': ['PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_K1)', 256],
    'test_ec_curve25519_priv': ['PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY)', 255],
    'test_ec_curve25519_pub': ['PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_MONTGOMERY)', 255],
    'test_ec_curve448_priv': ['PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY)', 448],
    'test_ec_curve448_pub': ['PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_MONTGOMERY)', 448],
}

def convert_der_to_c(array_name: str, key_data: bytearray) -> str:
    """Convert a DER content to a C array."""
    output_text = "const unsigned char {}[] = {{\n".format(array_name)

    def get_data_chunk(data):
        for index in range(0, len(data), BYTES_PER_LINE):
            yield data[index : index + BYTES_PER_LINE]

    for bytes_chunk in get_data_chunk(key_data):
        new_line = '    ' + ', '.join(['{:#04x}'.format(b) for b in bytes_chunk])
        output_text = output_text + new_line + ",\n"

    output_text = output_text + "};"

    return output_text

def main():
    # Remove output file if already existing.
    if os.path.exists(OUTPUT_HEADER_FILE):
        os.remove(OUTPUT_HEADER_FILE)

    output_file = open(OUTPUT_HEADER_FILE, 'at')
    output_file.write(
        "/*********************************************************************************\n" +
        " * This file was automatically generated from tests/scripts/generate_test_keys.py.\n" +
        " * Please do not edit it manually.\n" +
        " *********************************************************************************/\n"
    )

    for key in KEYS:
        key_type = KEYS[key][0]
        key_bitsize = KEYS[key][1]
        c_array = convert_der_to_c(key, ASYMMETRIC_KEY_DATA[key_type][key_bitsize])
        output_file.write("\n")
        output_file.write(c_array)
        output_file.write("\n")

if __name__ == '__main__':
    sys.exit(main())
