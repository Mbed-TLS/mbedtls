"""Mbed TLS build tree information and manipulation.
"""

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os

def looks_like_mbedtls_root(path: str) -> bool:
    """Whether the given directory looks like the root of the Mbed TLS source tree."""
    return all(os.path.isdir(os.path.join(path, subdir))
               for subdir in ['include', 'library', 'programs', 'tests'])

def chdir_to_root() -> None:
    """Detect the root of the Mbed TLS source tree and change to it.

    The current directory must be up to two levels deep inside an Mbed TLS
    source tree.
    """
    for d in [os.path.curdir,
              os.path.pardir,
              os.path.join(os.path.pardir, os.path.pardir)]:
        if looks_like_mbedtls_root(d):
            os.chdir(d)
            return
    raise Exception('Mbed TLS source tree not found')
