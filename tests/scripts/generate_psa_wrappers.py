#!/usr/bin/env python3
"""Generate wrapper functions for PSA function calls.
"""

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

import argparse
import os
from typing import Dict, List, Optional, Tuple

import scripts_path #pylint: disable=unused-import
from mbedtls_dev import build_tree
from mbedtls_dev import c_parsing_helper
from mbedtls_dev import c_wrapper_generator
from mbedtls_dev import typing_util


class PSAWrapperGenerator(c_wrapper_generator.Logging):
    """Generate a C source file containing wrapper functions for PSA Crypto API calls."""

    _CPP_GUARDS = 'defined(MBEDTLS_PSA_CRYPTO_C) && defined(MBEDTLS_TEST_HOOKS)'
    _WRAPPER_NAME_PREFIX = 'mbedtls_test_wrap_'
    _WRAPPER_NAME_SUFFIX = ''

    def __init__(self) -> None:
        super().__init__()
        self.set_stream('mbedtls_test_psa_wrappers_log_file')

    def gather_data(self) -> None:
        root_dir = build_tree.guess_mbedtls_root()
        for header_name in ['crypto.h', 'crypto_extra.h']:
            header_path = os.path.join(root_dir, 'include', 'psa', header_name)
            c_parsing_helper.read_function_declarations(self.functions, header_path)

    _SKIP_FUNCTIONS = frozenset([
        'mbedtls_psa_external_get_random', # not a library function
        'psa_get_key_domain_parameters', # client-side function
        'psa_get_key_slot_number', # client-side function
        'psa_key_derivation_verify_bytes', # not implemented yet
        'psa_key_derivation_verify_key', # not implemented yet
        'psa_set_key_domain_parameters', # client-side function
    ])

    def _skip_function(self, function: c_wrapper_generator.FunctionInfo) -> bool:
        if function.return_type != 'psa_status_t':
            return True
        if function.name in self._SKIP_FUNCTIONS:
            return True
        return False

    _PRINTF_TYPE_CAST = c_wrapper_generator.Logging._PRINTF_TYPE_CAST.copy()
    _PRINTF_TYPE_CAST.update({
        'psa_algorithm_t': 'unsigned',
        'psa_drv_slot_number_t': 'unsigned long long',
        'psa_key_derivation_step_t': 'int',
        'psa_key_id_t': 'unsigned',
        'psa_key_slot_number_t': 'unsigned long long',
        'psa_key_lifetime_t': 'unsigned',
        'psa_key_type_t': 'unsigned',
        'psa_key_usage_flags_t': 'unsigned',
        'psa_pake_role_t': 'int',
        'psa_pake_step_t': 'int',
        'psa_status_t': 'int',
    })

    # PAKE stuff: not implemented yet
    _PAKE_STUFF = frozenset([
        'psa_crypto_driver_pake_inputs_t *',
        'psa_pake_cipher_suite_t *',
    ])

    def _printf_parameters(self, typ: str, var: str) -> Tuple[str, List[str]]:
        #pylint: disable=too-many-return-statements
        if typ.startswith('const '):
            typ = typ[6:]
        if typ == 'uint8_t *':
            # Skip buffers
            return '', []
        if typ.endswith('operation_t *'):
            return '', []
        if typ in self._PAKE_STUFF:
            return '', []
        if typ == 'psa_key_attributes_t *':
            return (var +
                    '={id="MBEDTLS_SVC_KEY_ID_PRINTF_FORMAT",' +
                    ' lifetime=0x%08x, type=0x%08x, bits=%u, alg=%08x, usage=%08x}',
                    ['MBEDTLS_SVC_KEY_ID_PRINTF_ARGS(psa_get_key_id(' + var + '))'] +
                    ['(unsigned) psa_get_key_{}({})'.format(field, var)
                     for field in ['lifetime', 'type', 'bits', 'algorithm', 'usage_flags']])
        if typ == 'mbedtls_svc_key_id_t' or typ == 'mbedtls_svc_key_id_t *':
            expr = '*' + var if typ.endswith('*') else var
            return (var + '="MBEDTLS_SVC_KEY_ID_PRINTF_FORMAT"',
                    ['MBEDTLS_SVC_KEY_ID_PRINTF_ARGS(' + expr + ')'])
        return super()._printf_parameters(typ, var)

    def _return_variable_name(self,
                              function: c_wrapper_generator.FunctionInfo) -> str:
        """The name of the variable that will contain the return value."""
        if function.return_type == 'psa_status_t':
            return 'status'
        return super()._return_variable_name(function)

    _FUNCTION_GUARDS = c_wrapper_generator.Base._FUNCTION_GUARDS.copy() \
        #pylint: disable=protected-access
    _FUNCTION_GUARDS.update({
        'mbedtls_psa_register_se_key': 'defined(MBEDTLS_PSA_CRYPTO_SE_C)',
        'mbedtls_psa_inject_entropy': 'defined(MBEDTLS_PSA_INJECT_ENTROPY)',
        'mbedtls_psa_external_get_random': 'defined(MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG)',
        'mbedtls_psa_platform_get_builtin_key': 'defined(MBEDTLS_PSA_CRYPTO_BUILTIN_KEYS)',
    })

    def _write_prologue(self, out: typing_util.Writable, header: bool) -> None:
        super()._write_prologue(out, header)
        out.write("""
#if {}

#include <psa/crypto.h>

#include <test/psa_crypto_helpers.h>
#include <test/psa_test_wrappers.h>
"""
                  .format(self._CPP_GUARDS))

    def _write_epilogue(self, out: typing_util.Writable, header: bool) -> None:
        out.write("""
#endif /* {} */
"""
                  .format(self._CPP_GUARDS))
        super()._write_epilogue(out, header)


DEFAULT_C_OUTPUT_FILE_NAME = 'tests/src/psa_test_wrappers.c'
DEFAULT_H_OUTPUT_FILE_NAME = 'tests/include/test/psa_test_wrappers.h'

def main() -> None:
    parser = argparse.ArgumentParser(description=globals()['__doc__'])
    parser.add_argument('--output-c',
                        metavar='FILENAME',
                        default=DEFAULT_C_OUTPUT_FILE_NAME,
                        help=('Output .c file path (default: {}; skip .c output if empty)'
                              .format(DEFAULT_C_OUTPUT_FILE_NAME)))
    parser.add_argument('--output-h',
                        metavar='FILENAME',
                        default=DEFAULT_H_OUTPUT_FILE_NAME,
                        help=('Output .h file path (default: {}; skip .h output if empty)'
                              .format(DEFAULT_H_OUTPUT_FILE_NAME)))
    options = parser.parse_args()
    generator = PSAWrapperGenerator()
    generator.gather_data()
    if options.output_h:
        generator.write_h_file(options.output_h)
    if options.output_c:
        generator.write_c_file(options.output_c)

if __name__ == '__main__':
    main()
