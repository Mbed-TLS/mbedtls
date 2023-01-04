#!/usr/bin/env python3
"""Check or fix the code style by running Uncrustify.

Note: The code style enforced by this script is not yet introduced to
Mbed TLS. At present this script will only be used to prepare for a future
change of code style.
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
import argparse
import io
import os
import re
import subprocess
import sys
from typing import FrozenSet, List

UNCRUSTIFY_SUPPORTED_VERSION = "0.75.1"
CONFIG_FILE = ".uncrustify.cfg"
UNCRUSTIFY_EXE = "uncrustify"
UNCRUSTIFY_ARGS = ["-c", CONFIG_FILE]
STDOUT_UTF8 = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
STDERR_UTF8 = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')
CHECK_GENERATED_FILES = "tests/scripts/check-generated-files.sh"

def print_err(*args):
    print("Error: ", *args, file=STDERR_UTF8)

# Match FILENAME(s) in "check SCRIPT (FILENAME...)"
CHECK_CALL_RE = re.compile(r"\n\s*check\s+[^\s#$&*?;|]+([^\n#$&*?;|]+)",
                           re.ASCII)
def list_generated_files() -> FrozenSet[str]:
    """Return the names of generated files.

    We don't reformat generated files, since the result might be different
    from the output of the generator. Ideally the result of the generator
    would conform to the code style, but this would be difficult, especially
    with respect to the placement of line breaks in long logical lines.
    """
    # Parse check-generated-files.sh to get an up-to-date list of
    # generated files. Read the file rather than calling it so that
    # this script only depends on Git, Python and uncrustify, and not other
    # tools such as sh or grep which might not be available on Windows.
    # This introduces a limitation: check-generated-files.sh must have
    # the expected format and must list the files explicitly, not through
    # wildcards or command substitution.
    content = open(CHECK_GENERATED_FILES, encoding="utf-8").read()
    checks = re.findall(CHECK_CALL_RE, content)
    return frozenset(word for s in checks for word in s.split())

def get_src_files() -> List[str]:
    """
    Use git ls-files to get a list of the source files
    """
    git_ls_files_cmd = ["git", "ls-files",
                        "*.[hc]",
                        "tests/suites/*.function",
                        "scripts/data_files/*.fmt"]

    result = subprocess.run(git_ls_files_cmd, stdout=subprocess.PIPE, \
            stderr=STDERR_UTF8, check=False)

    if result.returncode != 0:
        print_err("git ls-files returned: " + str(result.returncode))
        return []
    else:
        generated_files = list_generated_files()
        src_files = str(result.stdout, "utf-8").split()
        # Don't correct style for third-party files (and, for simplicity,
        # companion files in the same subtree), or for automatically
        # generated files (we're correcting the templates instead).
        src_files = [filename for filename in src_files
                     if not (filename.startswith("3rdparty/") or
                             filename in generated_files)]
        return src_files

def get_uncrustify_version() -> str:
    """
    Get the version string from Uncrustify
    """
    result = subprocess.run([UNCRUSTIFY_EXE, "--version"], \
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode != 0:
        print_err("Could not get Uncrustify version:", str(result.stderr, "utf-8"))
        return ""
    else:
        return str(result.stdout, "utf-8")

def check_style_is_correct(src_file_list: List[str]) -> bool:
    """
    Check the code style and output a diff for each file whose style is
    incorrect.
    """
    style_correct = True
    for src_file in src_file_list:
        uncrustify_cmd = [UNCRUSTIFY_EXE] + UNCRUSTIFY_ARGS + [src_file]
        subprocess.run(uncrustify_cmd, stdout=subprocess.PIPE, \
                stderr=subprocess.PIPE, check=False)

        # Uncrustify makes changes to the code and places the result in a new
        # file with the extension ".uncrustify". To get the changes (if any)
        # simply diff the 2 files.
        diff_cmd = ["diff", "-u", src_file, src_file + ".uncrustify"]
        result = subprocess.run(diff_cmd, stdout=subprocess.PIPE, \
                stderr=STDERR_UTF8, check=False)
        if len(result.stdout) > 0:
            print(src_file + " - Incorrect code style.", file=STDOUT_UTF8)
            print("File changed - diff:", file=STDOUT_UTF8)
            print(str(result.stdout, "utf-8"), file=STDOUT_UTF8)
            style_correct = False
        else:
            print(src_file + " - OK.", file=STDOUT_UTF8)

        # Tidy up artifact
        os.remove(src_file + ".uncrustify")

    return style_correct

def fix_style_single_pass(src_file_list: List[str]) -> None:
    """
    Run Uncrustify once over the source files.
    """
    code_change_args = UNCRUSTIFY_ARGS + ["--no-backup"]
    for src_file in src_file_list:
        uncrustify_cmd = [UNCRUSTIFY_EXE] + code_change_args + [src_file]
        subprocess.run(uncrustify_cmd, check=False, stdout=STDOUT_UTF8, \
                stderr=STDERR_UTF8)

def fix_style(src_file_list: List[str]) -> int:
    """
    Fix the code style. This takes 2 passes of Uncrustify.
    """
    fix_style_single_pass(src_file_list)
    fix_style_single_pass(src_file_list)

    # Guard against future changes that cause the codebase to require
    # more passes.
    if not check_style_is_correct(src_file_list):
        print("Code style still incorrect after second run of Uncrustify.")
        return 1
    else:
        return 0

def main() -> int:
    """
    Main with command line arguments.
    """
    uncrustify_version = get_uncrustify_version().strip()
    if UNCRUSTIFY_SUPPORTED_VERSION not in uncrustify_version:
        print("Warning: Using unsupported Uncrustify version '" \
                + uncrustify_version + "' (Note: The only supported version" \
                "is " + UNCRUSTIFY_SUPPORTED_VERSION + ")", file=STDOUT_UTF8)

    src_files = get_src_files()

    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--fix', action='store_true', \
            help='modify source files to fix the code style')

    args = parser.parse_args()

    if args.fix:
        # Fix mode
        return fix_style(src_files)
    else:
        # Check mode
        if check_style_is_correct(src_files):
            return 0
        else:
            return 1

if __name__ == '__main__':
    sys.exit(main())
