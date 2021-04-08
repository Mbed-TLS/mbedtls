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

import itertools
import re
from typing import Dict, Iterable, Iterator, List, Set


class PSAMacroEnumerator:
    """Information about constructors of various PSA Crypto types.

    This includes macro names as well as information about their arguments
    when applicable.

    This class only provides ways to enumerate expressions that evaluate to
    values of the covered types. Derived classes are expected to populate
    the set of known constructors of each kind, as well as populate
    `self.arguments_for` for arguments that are not of a kind that is
    enumerated here.
    """

    def __init__(self) -> None:
        """Set up an empty set of known constructor macros.
        """
        self.statuses = set() #type: Set[str]
        self.algorithms = set() #type: Set[str]
        self.ecc_curves = set() #type: Set[str]
        self.dh_groups = set() #type: Set[str]
        self.key_types = set() #type: Set[str]
        self.key_usage_flags = set() #type: Set[str]
        self.hash_algorithms = set() #type: Set[str]
        self.mac_algorithms = set() #type: Set[str]
        self.ka_algorithms = set() #type: Set[str]
        self.kdf_algorithms = set() #type: Set[str]
        self.aead_algorithms = set() #type: Set[str]
        # macro name -> list of argument names
        self.argspecs = {} #type: Dict[str, List[str]]
        # argument name -> list of values
        self.arguments_for = {
            'mac_length': [],
            'min_mac_length': [],
            'tag_length': [],
            'min_tag_length': [],
        } #type: Dict[str, List[str]]

    def gather_arguments(self) -> None:
        """Populate the list of values for macro arguments.

        Call this after parsing all the inputs.
        """
        self.arguments_for['hash_alg'] = sorted(self.hash_algorithms)
        self.arguments_for['mac_alg'] = sorted(self.mac_algorithms)
        self.arguments_for['ka_alg'] = sorted(self.ka_algorithms)
        self.arguments_for['kdf_alg'] = sorted(self.kdf_algorithms)
        self.arguments_for['aead_alg'] = sorted(self.aead_algorithms)
        self.arguments_for['curve'] = sorted(self.ecc_curves)
        self.arguments_for['group'] = sorted(self.dh_groups)

    @staticmethod
    def _format_arguments(name: str, arguments: Iterable[str]) -> str:
        """Format a macro call with arguments.."""
        return name + '(' + ', '.join(arguments) + ')'

    _argument_split_re = re.compile(r' *, *')
    @classmethod
    def _argument_split(cls, arguments: str) -> List[str]:
        return re.split(cls._argument_split_re, arguments)

    def distribute_arguments(self, name: str) -> Iterator[str]:
        """Generate macro calls with each tested argument set.

        If name is a macro without arguments, just yield "name".
        If name is a macro with arguments, yield a series of
        "name(arg1,...,argN)" where each argument takes each possible
        value at least once.
        """
        try:
            if name not in self.argspecs:
                yield name
                return
            argspec = self.argspecs[name]
            if argspec == []:
                yield name + '()'
                return
            argument_lists = [self.arguments_for[arg] for arg in argspec]
            arguments = [values[0] for values in argument_lists]
            yield self._format_arguments(name, arguments)
            # Dear Pylint, enumerate won't work here since we're modifying
            # the array.
            # pylint: disable=consider-using-enumerate
            for i in range(len(arguments)):
                for value in argument_lists[i][1:]:
                    arguments[i] = value
                    yield self._format_arguments(name, arguments)
                arguments[i] = argument_lists[0][0]
        except BaseException as e:
            raise Exception('distribute_arguments({})'.format(name)) from e

    def generate_expressions(self, names: Iterable[str]) -> Iterator[str]:
        """Generate expressions covering values constructed from the given names.

        `names` can be any iterable collection of macro names.

        For example:
        * ``generate_expressions(['PSA_ALG_CMAC', 'PSA_ALG_HMAC'])``
          generates ``'PSA_ALG_CMAC'`` as well as ``'PSA_ALG_HMAC(h)'`` for
          every known hash algorithm ``h``.
        * ``macros.generate_expressions(macros.key_types)`` generates all
          key types.
        """
        return itertools.chain(*map(self.distribute_arguments, names))


class PSAMacroCollector(PSAMacroEnumerator):
    """Collect PSA crypto macro definitions from C header files.
    """

    def __init__(self, include_intermediate: bool = False) -> None:
        """Set up an object to collect PSA macro definitions.

        Call the read_file method of the constructed object on each header file.

        * include_intermediate: if true, include intermediate macros such as
          PSA_XXX_BASE that do not designate semantic values.
        """
        super().__init__()
        self.include_intermediate = include_intermediate
        self.key_types_from_curve = {} #type: Dict[str, str]
        self.key_types_from_group = {} #type: Dict[str, str]
        self.algorithms_from_hash = {} #type: Dict[str, str]

    def is_internal_name(self, name: str) -> bool:
        """Whether this is an internal macro. Internal macros will be skipped."""
        if not self.include_intermediate:
            if name.endswith('_BASE') or name.endswith('_NONE'):
                return True
            if '_CATEGORY_' in name:
                return True
        return name.endswith('_FLAG') or name.endswith('_MASK')

    def record_algorithm_subtype(self, name: str, expansion: str) -> None:
        """Record the subtype of an algorithm constructor.

        Given a ``PSA_ALG_xxx`` macro name and its expansion, if the algorithm
        is of a subtype that is tracked in its own set, add it to the relevant
        set.
        """
        # This code is very ad hoc and fragile. It should be replaced by
        # something more robust.
        if re.match(r'MAC(?:_|\Z)', name):
            self.mac_algorithms.add(name)
        elif re.match(r'KDF(?:_|\Z)', name):
            self.kdf_algorithms.add(name)
        elif re.search(r'0x020000[0-9A-Fa-f]{2}', expansion):
            self.hash_algorithms.add(name)
        elif re.search(r'0x03[0-9A-Fa-f]{6}', expansion):
            self.mac_algorithms.add(name)
        elif re.search(r'0x05[0-9A-Fa-f]{6}', expansion):
            self.aead_algorithms.add(name)
        elif re.search(r'0x09[0-9A-Fa-f]{2}0000', expansion):
            self.ka_algorithms.add(name)
        elif re.search(r'0x08[0-9A-Fa-f]{6}', expansion):
            self.kdf_algorithms.add(name)

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
        if parameter:
            self.argspecs[name] = [parameter]
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
            self.record_algorithm_subtype(name, expansion)
        elif name.startswith('PSA_ALG_') and parameter == 'hash_alg':
            if name in ['PSA_ALG_DSA', 'PSA_ALG_ECDSA']:
                # A naming irregularity
                tester = name[:8] + 'IS_RANDOMIZED_' + name[8:]
            else:
                tester = name[:8] + 'IS_' + name[8:]
            self.algorithms_from_hash[name] = tester
        elif name.startswith('PSA_KEY_USAGE_') and not parameter:
            self.key_usage_flags.add(name)
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
