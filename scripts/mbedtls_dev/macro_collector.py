"""Collect macro definitions from header files.
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

import re

class PSAMacroCollector:
    """Collect PSA crypto macro definitions from C header files.
    """

    def __init__(self, include_intermediate=False):
        """Set up an object to collect PSA macro definitions.

        Call the read_file method of the constructed object on each header file.

        * include_intermediate: if true, include intermediate macros such as
          PSA_XXX_BASE that do not designate semantic values.
        """
        self.include_intermediate = include_intermediate
        self.statuses = set()
        self.key_types = set()
        self.key_types_from_curve = {}
        self.key_types_from_group = {}
        self.ecc_curves = set()
        self.dh_groups = set()
        self.algorithms = set()
        self.hash_algorithms = set()
        self.ka_algorithms = set()
        self.algorithms_from_hash = {}
        self.key_usages = set()

    def is_internal_name(self, name):
        """Whether this is an internal macro. Internal macros will be skipped."""
        if not self.include_intermediate:
            if name.endswith('_BASE') or name.endswith('_NONE'):
                return True
            if '_CATEGORY_' in name:
                return True
        return name.endswith('_FLAG') or name.endswith('_MASK')

    # "#define" followed by a macro name with either no parameters
    # or a single parameter and a non-empty expansion.
    # Grab the macro name in group 1, the parameter name if any in group 2
    # and the expansion in group 3.
    _define_directive_re = re.compile(r'\s*#\s*define\s+(\w+)' +
                                      r'(?:\s+|\((\w+)\)\s*)' +
                                      r'(.+)')
    _deprecated_definition_re = re.compile(r'\s*MBEDTLS_DEPRECATED')

    def read_line(self, line):
        """Parse a C header line and record the PSA identifier it defines if any.
        This function analyzes lines that start with "#define PSA_"
        (up to non-significant whitespace) and skips all non-matching lines.
        """
        # pylint: disable=too-many-branches
        m = re.match(self._define_directive_re, line)
        if not m:
            return
        name, parameter, expansion = m.groups()
        expansion = re.sub(r'/\*.*?\*/|//.*', r' ', expansion)
        if re.match(self._deprecated_definition_re, expansion):
            # Skip deprecated values, which are assumed to be
            # backward compatibility aliases that share
            # numerical values with non-deprecated values.
            return
        if self.is_internal_name(name):
            # Macro only to build actual values
            return
        elif (name.startswith('PSA_ERROR_') or name == 'PSA_SUCCESS') \
           and not parameter:
            self.statuses.add(name)
        elif name.startswith('PSA_KEY_TYPE_') and not parameter:
            self.key_types.add(name)
        elif name.startswith('PSA_KEY_TYPE_') and parameter == 'curve':
            self.key_types_from_curve[name] = name[:13] + 'IS_' + name[13:]
        elif name.startswith('PSA_KEY_TYPE_') and parameter == 'group':
            self.key_types_from_group[name] = name[:13] + 'IS_' + name[13:]
        elif name.startswith('PSA_ECC_FAMILY_') and not parameter:
            self.ecc_curves.add(name)
        elif name.startswith('PSA_DH_FAMILY_') and not parameter:
            self.dh_groups.add(name)
        elif name.startswith('PSA_ALG_') and not parameter:
            if name in ['PSA_ALG_ECDSA_BASE',
                        'PSA_ALG_RSA_PKCS1V15_SIGN_BASE']:
                # Ad hoc skipping of duplicate names for some numerical values
                return
            self.algorithms.add(name)
            # Ad hoc detection of hash algorithms
            if re.search(r'0x020000[0-9A-Fa-f]{2}', expansion):
                self.hash_algorithms.add(name)
            # Ad hoc detection of key agreement algorithms
            if re.search(r'0x09[0-9A-Fa-f]{2}0000', expansion):
                self.ka_algorithms.add(name)
        elif name.startswith('PSA_ALG_') and parameter == 'hash_alg':
            if name in ['PSA_ALG_DSA', 'PSA_ALG_ECDSA']:
                # A naming irregularity
                tester = name[:8] + 'IS_RANDOMIZED_' + name[8:]
            else:
                tester = name[:8] + 'IS_' + name[8:]
            self.algorithms_from_hash[name] = tester
        elif name.startswith('PSA_KEY_USAGE_') and not parameter:
            self.key_usages.add(name)
        else:
            # Other macro without parameter
            return

    _nonascii_re = re.compile(rb'[^\x00-\x7f]+')
    _continued_line_re = re.compile(rb'\\\r?\n\Z')
    def read_file(self, header_file):
        for line in header_file:
            m = re.search(self._continued_line_re, line)
            while m:
                cont = next(header_file)
                line = line[:m.start(0)] + cont
                m = re.search(self._continued_line_re, line)
            line = re.sub(self._nonascii_re, rb'', line).decode('ascii')
            self.read_line(line)
