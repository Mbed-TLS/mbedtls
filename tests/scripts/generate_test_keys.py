#!/usr/bin/env python3

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

"""Module generating EC and RSA keys to be used in test_suite_pk instead of
generating the required key at run time. This helps speeding up testing."""

import os
import sys
from typing import Iterator
import re
# pylint: disable=wrong-import-position
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__)) + "/"
sys.path.append(SCRIPT_DIR + "../../scripts/")
from mbedtls_dev.asymmetric_key_data import ASYMMETRIC_KEY_DATA
import scripts_path # pylint: disable=unused-import

OUTPUT_HEADER_FILE = SCRIPT_DIR + "../src/test_keys.h"
BYTES_PER_LINE = 16

def c_byte_array_literal_content(array_name: str, key_data: bytes) -> Iterator[str]:
    yield 'const unsigned char '
    yield array_name
    yield '[] = {'
    for index in range(0, len(key_data), BYTES_PER_LINE):
        yield '\n   '
        for b in key_data[index:index + BYTES_PER_LINE]:
            yield ' {:#04x},'.format(b)
    yield '\n};'

def convert_der_to_c(array_name: str, key_data: bytes) -> str:
    return ''.join(c_byte_array_literal_content(array_name, key_data))

EC_NAME_CONVERSION = {
    'PSA_ECC_FAMILY_SECP_K1': ['secp', 'k1'],
    'PSA_ECC_FAMILY_SECP_R1': ['secp', 'r1'],
    'PSA_ECC_FAMILY_BRAINPOOL_P_R1': ['bp', 'r1'],
    'PSA_ECC_FAMILY_MONTGOMERY': ['curve', ''],
}

def get_key_type(key: str) -> str:
    if re.match('PSA_KEY_TYPE_RSA_.*', key):
        return "rsa"
    elif re.match('PSA_KEY_TYPE_ECC_.*', key):
        return "ec"
    else:
        print("Unhandled key type {}".format(key))
        return "unknown"

def get_ec_key_family(key: str) -> str:
    match = re.search(r'.*\((.*)\)', key)
    if match is None:
        raise Exception("Unable to get EC family from {}".format(key))
    return match.group(1)

def get_key_role(key_type: str) -> str:
    if re.match('PSA_KEY_TYPE_.*_KEY_PAIR', key_type):
        return "priv"
    else:
        return "pub"

def main() -> None:
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

    for key in ASYMMETRIC_KEY_DATA:
        key_type = get_key_type(key)
        # Ignore keys which are not EC or RSA
        if key_type == "unknown":
            continue
        # Ignore undesired EC keys
        if key_type == "ec":
            ec_family = get_ec_key_family(key)
            if not ec_family in EC_NAME_CONVERSION:
                continue
        role = get_key_role(key)

        for bits in ASYMMETRIC_KEY_DATA[key]:
            # Create output array name
            if key_type == "rsa":
                array_name = "_".join(["test", key_type, str(bits), role])
            else:
                prefix = EC_NAME_CONVERSION[ec_family][0]
                suffix = EC_NAME_CONVERSION[ec_family][1]
                curve = "".join([prefix, str(bits), suffix])
                array_name = "_".join(["test", key_type, curve, role])
            # Convert bytearray to C array
            c_array = convert_der_to_c(array_name, ASYMMETRIC_KEY_DATA[key][bits])
            # Write the C array to the output file
            output_file.write("\n")
            output_file.write(c_array)
            output_file.write("\n")

if __name__ == '__main__':
    main()
