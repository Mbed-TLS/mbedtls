#!/usr/bin/env python3

"""Edit test cases to use PSA dependencies instead of classic dependencies.
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
import re
import sys

def updated_dependencies(file_name, function_name, arguments, dependencies):
    """Rework the list of dependencies into PSA_WANT_xxx.

    Remove classic crypto dependencies such as MBEDTLS_RSA_C,
    MBEDTLS_PKCS1_V15, etc.

    Add systematic PSA_WANT_xxx dependencies based on the called function and
    its arguments, replacing existing PSA_WANT_xxx dependencies.
    """
    return dependencies #TODO

def keep_manual_dependencies(file_name, function_name, arguments):
    #pylint: disable=unused-argument
    """Declare test functions with unusual dependencies here."""
    return False

def process_data_stanza(stanza, file_name, test_case_number):
    """Update PSA crypto dependencies in one Mbed TLS test case.

    stanza is the test case text (including the description, the dependencies,
    the line with the function and arguments, and optionally comments). Return
    a new stanza with an updated dependency line, preserving everything else
    (description, comments, arguments, etc.).
    """
    if not stanza.lstrip('\n'):
        # Just blank lines
        return stanza
    # Expect 2 or 3 non-comment lines: description, optional dependencies,
    # function-and-arguments.
    content_matches = list(re.finditer(r'^[\t ]*([^\t #].*)$', stanza, re.M))
    if len(content_matches) < 2:
        raise Exception('Not enough content lines in paragraph {} in {}'
                        .format(test_case_number, file_name))
    if len(content_matches) > 3:
        raise Exception('Too many content lines in paragraph {} in {}'
                        .format(test_case_number, file_name))
    arguments = content_matches[-1].group(0).split(':')
    function_name = arguments.pop(0)
    if keep_manual_dependencies(file_name, function_name, arguments):
        return stanza
    if len(content_matches) == 2:
        # Insert a line for the dependencies. If it turns out that there are
        # no dependencies, we'll remove that empty line below.
        dependencies_location = content_matches[-1].start()
        text_before = stanza[:dependencies_location]
        text_after = '\n' + stanza[dependencies_location:]
        old_dependencies = []
        dependencies_leader = 'depends_on:'
    else:
        dependencies_match = content_matches[-2]
        text_before = stanza[:dependencies_match.start()]
        text_after = stanza[dependencies_match.end():]
        old_dependencies = dependencies_match.group(0).split(':')
        dependencies_leader = old_dependencies.pop(0) + ':'
        if dependencies_leader != 'depends_on:':
            raise Exception('Next-to-last line does not start with "depends_on:"'
                            ' in paragraph {} in {}'
                            .format(test_case_number, file_name))
    new_dependencies = updated_dependencies(file_name, function_name, arguments,
                                            old_dependencies)
    if new_dependencies:
        stanza = (text_before +
                  dependencies_leader + ':'.join(new_dependencies) +
                  text_after)
    else:
        # The dependencies have become empty. Remove the depends_on: line.
        assert text_after[0] == '\n'
        stanza = text_before + text_after[1:]
    return stanza

def process_data_file(file_name, old_content):
    """Update PSA crypto dependencies in an Mbed TLS test suite data file.

    Process old_content (the old content of the file) and return the new content.
    """
    old_stanzas = old_content.split('\n\n')
    new_stanzas = [process_data_stanza(stanza, file_name, n)
                   for n, stanza in enumerate(old_stanzas, start=1)]
    return '\n\n'.join(new_stanzas)

def update_file(file_name, old_content, new_content):
    """Update the given file with the given new content.

    Replace the existing file. The previous version is renamed to *.bak.
    Don't modify the file if the content was unchanged.
    """
    if new_content == old_content:
        return
    backup = file_name + '.bak'
    tmp = file_name + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as new_file:
        new_file.write(new_content)
    os.replace(file_name, backup)
    os.replace(tmp, file_name)

def process_file(file_name):
    """Update PSA crypto dependencies in an Mbed TLS test suite data file.

    Replace the existing file. The previous version is renamed to *.bak.
    Don't modify the file if the content was unchanged.
    """
    old_content = open(file_name, encoding='utf-8').read()
    if file_name.endswith('.data'):
        new_content = process_data_file(file_name, old_content)
    else:
        raise Exception('File type not recognized: {}'
                        .format(file_name))
    update_file(file_name, old_content, new_content)

def main(args):
    for file_name in args:
        process_file(file_name)

if __name__ == '__main__':
    main(sys.argv[1:])
