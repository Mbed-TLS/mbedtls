#!/usr/bin/env python3
"""Generate the list of structure fields in a form usable from Python.
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

import glob
import json
import re
from typing import Dict, List
from typing_extensions import TypedDict

Data = TypedDict('Data', {  #pylint: disable=invalid-name
    'private_fields': Dict[str, List[str]],
    'public_fields': Dict[str, List[str]],
})

COMMENT_RE = re.compile(r'//[^\n]+|/\*.*?\*/')
STRUCT_DEFINITION_RE = \
    re.compile(r'\ntypedef struct\b\s*\w*\s*\{(.*?)\}\s*(\w+);',
               re.DOTALL)
FIELD_RE = re.compile(
    r'\b(?:' +
    '|'.join([
        r'(?P<public_name>\w+)',
        r'MBEDTLS_PRIVATE\s*\(\s*(?P<private_name>\w+)\s*\)',
        r'\(\s*\**\s*(?:' + # function (pointer) name and parameters
        '|'.join([r'(?P<public_fname>\w+)',
                  r'MBEDTLS_PRIVATE\s*\(\s*(?P<private_fname>\w+)\s*\)']) +
        r')\s*\)\s*\([^;]*?\)'
    ]) +
    r')(?:\s*\[[^;]*?\])*' + # optional array lengths
    r'\s*;'
)

def list_type_fields(private_list: List[str],
                     public_list: List[str],
                     body: str) -> None:
    """Add the field names defined in body to the given lists."""
    for m in re.finditer(FIELD_RE, body):
        public_name = m.group('public_name') or m.group('public_fname')
        if public_name:
            public_list.append(public_name)
        private_name = m.group('private_name') or m.group('private_fname')
        if private_name:
            private_list.append(private_name)

def list_file_fields(header: str, data: Data) -> None:
    """Parse structure definitions in a header file and record their field names."""
    content = open(header).read()
    # Strip comments so as not to be confused by their contents.
    # Don't bother with string literals: in Mbed TLS headers, there shouldn't
    # be any troublesome ones.
    content = re.sub(COMMENT_RE, r' ', content)
    for m in re.finditer(STRUCT_DEFINITION_RE, content):
        body, type_name = m.groups()
        data['private_fields'][type_name] = []
        data['public_fields'][type_name] = []
        list_type_fields(data['private_fields'][type_name],
                         data['public_fields'][type_name],
                         body)

def list_fields_to_file(headers: List[str], output_file: str) -> None:
    data = {
        'private_fields': {},
        'public_fields': {},
    } #type: Data
    for header in headers:
        list_file_fields(header, data)
    with open(output_file, 'w') as out:
        json.dump(data, out, sort_keys=True)

JSON_FILE = 'scripts/data_files/2to3-knowledge-generated.json'
if __name__ == '__main__':
    list_fields_to_file(glob.glob('include/mbedtls/*.h'), JSON_FILE)
