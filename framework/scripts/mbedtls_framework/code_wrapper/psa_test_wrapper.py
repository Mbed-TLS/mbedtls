"""Generate wrapper functions for PSA function calls.
"""

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

import argparse
import itertools
import os
from typing import Iterator, List, Collection, Optional, Tuple

from .. import build_tree
from .. import c_parsing_helper
from .. import c_wrapper_generator
from .. import typing_util

from .psa_buffer import BufferParameter
from .psa_wrapper import PSAWrapper, PSALoggingWrapper, PSAWrapperConfiguration

class PSATestWrapper(PSAWrapper):
    """Generate a C source file containing wrapper functions for PSA Crypto API calls."""

    _WRAPPER_NAME_PREFIX = 'mbedtls_test_wrap_'
    _WRAPPER_NAME_SUFFIX = ''

    _PSA_WRAPPER_INCLUDES = ['<psa/crypto.h>',
                             '<test/memory.h>',
                             '<test/psa_crypto_helpers.h>',
                             '<test/psa_test_wrappers.h>']

class PSALoggingTestWrapper(PSATestWrapper, PSALoggingWrapper):
    """Generate a C source file containing wrapper functions that log PSA Crypto API calls."""

    def __init__(self, out_h_f: str,
                       out_c_f: str,
                       stream: str,
                       in_headers: Optional[List[str]] = None) -> None:
        super().__init__(out_h_f, out_c_f, stream, in_headers)

