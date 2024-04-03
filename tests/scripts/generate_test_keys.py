#!/usr/bin/env python3

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

"""Module generating EC and RSA keys to be used in test_suite_pk instead of
generating the required key at run time. This helps speeding up testing."""

import os
import sys
import subprocess

KEY_GEN = "./programs/pkey/gen_key"
TMP_DER_FILE = "tmp_key.der"
OUTPUT_HEADER_FILE = "./tests/src/test_keys.h"
BYTES_PER_LINE = 12

KEYS = {
    # RSA keys
    'test_rsa_1024': ['rsa', '1024'],
    'test_rsa_1026': ['rsa', '1026'],
    'test_rsa_1028': ['rsa', '1028'],
    'test_rsa_1030': ['rsa', '1030'],
    'test_rsa_2048': ['rsa', '2048'],
    'test_rsa_4096': ['rsa', '4096'],
    # EC keys
    'test_ec_secp192r1': ['ec', 'secp192r1'],
    'test_ec_secp224r1': ['ec', 'secp224r1'],
    'test_ec_secp256r1': ['ec', 'secp256r1'],
    'test_ec_secp384r1': ['ec', 'secp384r1'],
    'test_ec_secp521r1': ['ec', 'secp521r1'],
    'test_ec_bp256r1': ['ec', 'brainpoolP256r1'],
    'test_ec_bp384r1': ['ec', 'brainpoolP384r1'],
    'test_ec_bp512r1': ['ec', 'brainpoolP512r1'],
    'test_ec_curve25519': ['ec', 'x25519'],
    'test_ec_secp192k1': ['ec', 'secp192k1'],
    'test_ec_secp256k1': ['ec', 'secp256k1'],
    'test_ec_curve448': ['ec', 'x448'],
}

def generate_der_file(curve_type: str, curve_or_bits: str):
    if not os.path.exists(KEY_GEN):
        raise Exception(KEY_GEN + " does not exist. Please build it before running this script.")
    if curve_type == 'ec':
        cob_param = 'ec_curve=' + curve_or_bits
    else:
        cob_param = 'rsa_keysize=' + curve_or_bits

    subprocess.run([KEY_GEN, 'type=' + curve_type, cob_param,
                    'format=der', 'filename=' + TMP_DER_FILE], check=True)

def convert_der_to_c(array_name: str) -> str:
    """Convert a DER file content to a C array. The name of such array is
    provided as input parameter. The file to be converted is the temporary
    TMP_DER_FILE."""
    output_text = "const unsigned char {}[] = {{\n".format(array_name)

    with open(TMP_DER_FILE, 'rb') as input_file:
        data_block = input_file.read(BYTES_PER_LINE)
        while data_block:
            new_line = '    ' + ', '.join(['{:#04x}'.format(b) for b in data_block])
            output_text = output_text + new_line + ",\n"
            data_block = input_file.read(BYTES_PER_LINE)

    output_text = output_text + "};\n"

    return output_text

def main():
    # Remove intermediate and output files if already existing.
    if os.path.exists(OUTPUT_HEADER_FILE):
        os.remove(OUTPUT_HEADER_FILE)
    if os.path.exists(TMP_DER_FILE):
        os.remove(TMP_DER_FILE)

    output_file = open(OUTPUT_HEADER_FILE, 'at')
    output_file.write(
        "/*********************************************************************************\n" +
        " * This file was automatically generated from tests/scripts/generate_test_keys.py.\n" +
        " * Please do not edit it manually.\n" +
        " *********************************************************************************/\n" +
        "\n"
    )

    add_newline = False
    for key in KEYS:
        # Use gen_key tool to generate the desired key (in DER format) and save
        # it into a temporary file.
        generate_der_file(KEYS[key][0], KEYS[key][1])
        # Convert the key from binary format to a C array and append the result
        # to the output header file.
        if add_newline:
            output_file.write("\n")
        c_data = convert_der_to_c(key)
        output_file.write(c_data)
        # Remove the temporary key file.
        os.remove(TMP_DER_FILE)
        add_newline = True

if __name__ == '__main__':
    sys.exit(main())
