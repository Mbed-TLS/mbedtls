"""Mbed TLS build tree information and manipulation.
"""

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
#

import os
import inspect

def looks_like_psa_crypto_root(path: str) -> bool:
    """Whether the given directory looks like the root of the PSA Crypto source tree."""
    return all(os.path.isdir(os.path.join(path, subdir))
               for subdir in ['include', 'core', 'drivers', 'programs', 'tests'])

def looks_like_mbedtls_root(path: str) -> bool:
    """Whether the given directory looks like the root of the Mbed TLS source tree."""
    return all(os.path.isdir(os.path.join(path, subdir))
               for subdir in ['include', 'library', 'programs', 'tests'])

def looks_like_root(path: str) -> bool:
    return looks_like_psa_crypto_root(path) or looks_like_mbedtls_root(path)

def check_repo_path():
    """
    Check that the current working directory is the project root, and throw
    an exception if not.
    """
    if not all(os.path.isdir(d) for d in ["include", "library", "tests"]):
        raise Exception("This script must be run from Mbed TLS root")

def chdir_to_root() -> None:
    """Detect the root of the Mbed TLS source tree and change to it.

    The current directory must be up to two levels deep inside an Mbed TLS
    source tree.
    """
    for d in [os.path.curdir,
              os.path.pardir,
              os.path.join(os.path.pardir, os.path.pardir)]:
        if looks_like_root(d):
            os.chdir(d)
            return
    raise Exception('Mbed TLS source tree not found')


def guess_mbedtls_root():
    """Guess mbedTLS source code directory.

    Return the first possible mbedTLS root directory
    """
    dirs = set({})
    for frame in inspect.stack():
        path = os.path.dirname(frame.filename)
        for d in ['.', os.path.pardir] \
                 + [os.path.join(*([os.path.pardir]*i)) for i in range(2, 10)]:
            d = os.path.abspath(os.path.join(path, d))
            if d in dirs:
                continue
            dirs.add(d)
            if looks_like_root(d):
                return d
    raise Exception('Mbed TLS source tree not found')
