#!/usr/bin/env python3

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

"""Module generating EC and RSA keys to be used in test_suite_pk instead of
generating the required key at run time. This helps speeding up testing."""

from typing import Iterator, List, Tuple
import re
import argparse
import scripts_path # pylint: disable=unused-import
from mbedtls_dev.asymmetric_key_data import ASYMMETRIC_KEY_DATA
from mbedtls_dev.build_tree import guess_project_root

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

# Legacy EC group ID do not support all the key types that PSA does, so the
# following dictionaries are used for:
# - getting prefix/suffix for legacy curve names
# - understand if the curve is supported in legacy symbols (MBEDTLS_ECP_DP_...)
EC_NAME_CONVERSION = {
    'PSA_ECC_FAMILY_SECP_K1': {
        192: ('secp', 'k1'),
        224: ('secp', 'k1'),
        256: ('secp', 'k1')
    },
    'PSA_ECC_FAMILY_SECP_R1': {
        192: ('secp', 'r1'),
        224: ('secp', 'r1'),
        256: ('secp', 'r1'),
        384: ('secp', 'r1'),
        521: ('secp', 'r1')
    },
    'PSA_ECC_FAMILY_BRAINPOOL_P_R1': {
        256: ('bp', 'r1'),
        384: ('bp', 'r1'),
        512: ('bp', 'r1')
    },
    'PSA_ECC_FAMILY_MONTGOMERY': {
        255: ('curve', '19'),
        448: ('curve', '')
    }
}

def get_ec_curve_name(priv_key: str, bits: int) -> str:
    ec_family = get_ec_key_family(priv_key)
    try:
        prefix = EC_NAME_CONVERSION[ec_family][bits][0]
        suffix = EC_NAME_CONVERSION[ec_family][bits][1]
    except KeyError:
        return ""
    return prefix + str(bits) + suffix

def get_look_up_table_entry(key_type: str, group_id_or_keybits: str,
                            priv_array_name: str, pub_array_name: str) -> Iterator[str]:
    if key_type == "ec":
        yield "    {{ {}, 0,\n".format(group_id_or_keybits)
    else:
        yield "    {{ 0, {},\n".format(group_id_or_keybits)
    yield "      {0}, sizeof({0}),\n".format(priv_array_name)
    yield "      {0}, sizeof({0}) }},".format(pub_array_name)


def write_output_file(output_file_name: str, arrays: str, look_up_table: str):
    with open(output_file_name, 'wt') as output:
        output.write("""\
/*********************************************************************************
 * This file was automatically generated from tests/scripts/generate_test_keys.py.
 * Please do not edit it manually.
 *********************************************************************************/
""")
        output.write(arrays)
        output.write("""
struct predefined_key_element {{
    int group_id;  // EC group ID; 0 for RSA keys
    int keybits;  // bits size of RSA key; 0 for EC keys
    const unsigned char *priv_key;
    size_t priv_key_len;
    const unsigned char *pub_key;
    size_t pub_key_len;
}};

struct predefined_key_element predefined_keys[] = {{
{}
}};

/* End of generated file */
""".format(look_up_table))

def collect_keys() -> Tuple[str, str]:
    """"
    This function reads key data from ASYMMETRIC_KEY_DATA and, only for the
    keys supported in legacy ECP/RSA modules, it returns 2 strings:
    - the 1st contains C arrays declaration of these keys and
    - the 2nd contains the final look-up table for all these arrays.
    """
    arrays = []
    look_up_table = []

    # Get a list of private keys only in order to get a single item for every
    # (key type, key bits) pair. We know that ASYMMETRIC_KEY_DATA
    # contains also the public counterpart.
    priv_keys = [key for key in ASYMMETRIC_KEY_DATA if '_KEY_PAIR' in key]
    priv_keys = sorted(priv_keys)

    for priv_key in priv_keys:
        key_type = get_key_type(priv_key)
        # Ignore keys which are not EC or RSA
        if key_type == "unknown":
            continue

        pub_key = re.sub('_KEY_PAIR', '_PUBLIC_KEY', priv_key)

        for bits in ASYMMETRIC_KEY_DATA[priv_key]:
            if key_type == "ec":
                curve = get_ec_curve_name(priv_key, bits)
                # Ignore EC curves unsupported in legacy symbols
                if curve == "":
                    continue
            # Create output array name
            if key_type == "rsa":
                array_name_base = "_".join(["test", key_type, str(bits)])
            else:
                array_name_base = "_".join(["test", key_type, curve])
            array_name_priv = array_name_base + "_priv"
            array_name_pub = array_name_base + "_pub"
            # Convert bytearray to C array
            c_array_priv = convert_der_to_c(array_name_priv, ASYMMETRIC_KEY_DATA[priv_key][bits])
            c_array_pub = convert_der_to_c(array_name_pub, ASYMMETRIC_KEY_DATA[pub_key][bits])
            # Write the C array to the output file
            arrays.append(''.join(["\n", c_array_priv, "\n", c_array_pub, "\n"]))
            # Update the lookup table
            if key_type == "ec":
                group_id_or_keybits = "MBEDTLS_ECP_DP_" + curve.upper()
            else:
                group_id_or_keybits = str(bits)
            look_up_table.append(''.join(get_look_up_table_entry(key_type, group_id_or_keybits,
                                                                 array_name_priv, array_name_pub)))

    return ''.join(arrays), '\n'.join(look_up_table)

def main() -> None:
    default_output_path = guess_project_root() + "/tests/src/test_keys.h"

    argparser = argparse.ArgumentParser()
    argparser.add_argument("--output", help="Output file", default=default_output_path)
    args = argparser.parse_args()

    output_file = args.output

    arrays, look_up_table = collect_keys()

    write_output_file(output_file, arrays, look_up_table)

if __name__ == '__main__':
    main()
