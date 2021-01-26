"""Knowledge about cryptographic mechanisms implemented in Mbed TLS.

This module is entirely based on the PSA API.
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
from typing import List, Optional

class KeyType:
    """Knowledge about a PSA key type."""

    def __init__(self, name: str, params: Optional[List[str]] = None):
        """Analyze a key type.

        The key type must be specified in PSA syntax. In its simplest form,
        this is a string 'PSA_KEY_TYPE_xxx' which is the name of a PSA key
        type macro. For key types that take arguments, the arguments can
        be passed either through the optional argument `params` or by
        passing an expression of the form 'PSA_KEY_TYPE_xxx(param1, param2)'
        as the a string.
        """
        self.name = name.strip()
        if params is None:
            if '(' in self.name:
                m = re.match(r'(\w+)\s*\((.*)\)\Z', self.name)
                assert m is not None
                self.name = m.group(1)
                params = ','.split(m.group(2))
        if params is None:
            self.params = params
        else:
            self.params = [param.strip() for param in params]
        self.expression = self.name
        if self.params is not None:
            self.expression += '(' + ', '.join(self.params) + ')'
        self.private_type = re.sub(r'_PUBLIC_KEY\Z', r'_KEY_PAIR', self.name)
