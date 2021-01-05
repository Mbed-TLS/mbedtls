#!/usr/bin/env python3

"""Extract defines create by header

Takes a single argument, which is the path to a header file.  This
program scans that header for conditionalized defines.  The intended
use is to scan config_psa.h to determine which legacy defines are
defined by it, so that they can be unset in the main config file.
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
import sys

# Parsing here is fairly naive, we look for defines of symbols, but we
# don't start until the first if defined.
ifdefined_re = re.compile(r'^#if defined')
define_re = re.compile(r'#define (MBEDTLS_[A-Z0-9_]+)')

def main():
    if len(sys.argv) != 2:
        print("Usage: {} path-to-header.h".format(sys.argv[0]))
        sys.exit(1)

    found = False
    seen = set()
    with open(sys.argv[1]) as fd:
        for line in fd:
            m = ifdefined_re.match(line)
            if m is not None:
                found = True
                continue

            if not found:
                continue

            m = define_re.match(line)
            if m is not None:
                define = m.group(1)
                if define in seen:
                    continue
                seen.add(define)
                print(define)

if __name__ == '__main__':
    main()
