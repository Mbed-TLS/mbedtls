#!/usr/bin/env python3

"""
This script is for comparing the size of the library files from two
different Git revisions within an Mbed TLS repository.
The results of the comparison is formatted as csv and stored at a
configurable location.
Note: must be run from Mbed TLS root.
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
import os
import re
import subprocess
import sys
import typing
from enum import Enum

from mbedtls_dev import typing_util
from mbedtls_dev import build_tree

class SupportedArch(Enum):
    """Supported architecture for code size measurement."""
    AARCH64 = 'aarch64'
    AARCH32 = 'aarch32'
    ARMV8_M = 'armv8-m'
    X86_64 = 'x86_64'
    X86 = 'x86'

CONFIG_TFM_MEDIUM_MBEDCRYPTO_H = "../configs/tfm_mbedcrypto_config_profile_medium.h"
CONFIG_TFM_MEDIUM_PSA_CRYPTO_H = "../configs/crypto_config_profile_medium.h"
class SupportedConfig(Enum):
    """Supported configuration for code size measurement."""
    DEFAULT = 'default'
    TFM_MEDIUM = 'tfm-medium'

# Static library
MBEDTLS_STATIC_LIB = {
    'CRYPTO': 'library/libmbedcrypto.a',
    'X509': 'library/libmbedx509.a',
    'TLS': 'library/libmbedtls.a',
}

# Configurations need to be tweaked for aarch32/aarch64 with armclang
ARCH_CONFIG_SET_FROM_DEFAULT = frozenset([
    'MBEDTLS_NO_PLATFORM_ENTROPY'
])
ARCH_CONFIG_UNSET_FROM_DEFAULT = frozenset([
    'MBEDTLS_FS_IO',
    'MBEDTLS_HAVE_TIME',
    'MBEDTLS_HAVE_TIME_DATE',
    'MBEDTLS_NET_C',
    'MBEDTLS_PSA_CRYPTO_STORAGE_C',
    'MBEDTLS_PSA_ITS_FILE_C',
    'MBEDTLS_TIMING_C'
])
ARCH_CONFIG_DICT = {
    'set': ARCH_CONFIG_SET_FROM_DEFAULT,
    'unset': ARCH_CONFIG_UNSET_FROM_DEFAULT,
}

DETECT_ARCH_CMD = "cc -dM -E - < /dev/null"
def detect_arch() -> str:
    """Auto-detect host architecture."""
    cc_output = subprocess.check_output(DETECT_ARCH_CMD, shell=True).decode()
    if "__aarch64__" in cc_output:
        return SupportedArch.AARCH64.value
    if "__arm__" in cc_output:
        return SupportedArch.AARCH32.value
    if "__x86_64__" in cc_output:
        return SupportedArch.X86_64.value
    if "__x86__" in cc_output:
        return SupportedArch.X86.value
    else:
        print("Unknown host architecture, cannot auto-detect arch.")
        sys.exit(1)

class CodeSizeInfo:
    """Gather information used to measure code size.

    It collects information about architecture, configuration in order to
    infer build command for code size measurement.
    """

    SupportedArchConfig = [
        "-a " + SupportedArch.AARCH64.value + " -c " + SupportedConfig.DEFAULT.value,
        "-a " + SupportedArch.AARCH32.value + " -c " + SupportedConfig.DEFAULT.value,
        "-a " + SupportedArch.X86_64.value  + " -c " + SupportedConfig.DEFAULT.value,
        "-a " + SupportedArch.X86.value     + " -c " + SupportedConfig.DEFAULT.value,
        "-a " + SupportedArch.ARMV8_M.value + " -c " + SupportedConfig.TFM_MEDIUM.value,
    ]

    def __init__(
            self,
            arch: str,
            config: str,
            c_compiler: str,
            sys_arch: str
    ) -> None:
        """
        arch: architecture to measure code size on.
        config: configuration type to measure code size with.
        sys_arch: TODO
        c_compiler: TODO
        make_command: command to build library (Inferred from arch and config).
        """
        self.arch = arch
        self.config = config
        self.sys_arch = sys_arch

        self.default_gcc = 'gcc'
        self.default_clang = 'clang'
        self.default_armclang = 'armclang'
        self.tweak_config = False
        self.c_compiler = self.set_c_compiler(c_compiler)
        self.make_command = self.set_make_command()

    def set_c_compiler(self, c_compiler: str) -> str:
        """TODO"""

        # Comment TODO: handle default config
        if self.config == SupportedConfig.DEFAULT.value:
            if c_compiler:
                if self.default_armclang in c_compiler and \
                    (self.arch != SupportedArch.AARCH64.value and \
                     self.arch != SupportedArch.AARCH32.value):
                    print("Error: armclang is not supported on:", self.arch)
                    sys.exit(1)
                else:
                    return c_compiler

        # Comment TODO: handle tfm-medium config
        elif self.config == SupportedConfig.TFM_MEDIUM.value:
            if c_compiler is None:
                return self.default_armclang
            elif self.default_armclang in c_compiler:
                return c_compiler
            else:
                print("Error: armclang is required to build configuration:",\
                       SupportedConfig.TFM_MEDIUM.value)
                sys.exit(1)

        return self.default_gcc

    def set_make_command(self) -> str:
        """Infer build command based on architecture and configuration."""

        if self.config == SupportedConfig.DEFAULT.value:
            if self.arch == self.sys_arch and self.c_compiler:
                return 'make -j lib CC={CC} CFLAGS=\'-Os \' ' \
                       .format(CC=self.c_compiler)
            elif self.arch == SupportedArch.AARCH64.value and \
                    self.default_armclang in self.c_compiler:
                self.tweak_config = True
                return 'make -j lib CC={CC} \
                        CFLAGS=\'--target=aarch64-arm-none-eabi -Os \' ' \
                       .format(CC=self.c_compiler)
            elif self.arch == SupportedArch.AARCH32.value and \
                    self.default_armclang in self.c_compiler:
                self.tweak_config = True
                return 'make -j lib CC={CC} \
                        CFLAGS=\'--target=arm-arm-none-eabi -Os \' ' \
                       .format(CC=self.c_compiler)

        elif self.arch == SupportedArch.ARMV8_M.value and \
             self.config == SupportedConfig.TFM_MEDIUM.value:
            return \
                 'make -j lib CC={CC} \
                  CFLAGS=\'--target=arm-arm-none-eabi -mcpu=cortex-m33 -Os \
                 -DMBEDTLS_CONFIG_FILE=\\\"{MBEDCRYPTO_CONFIG}\\\" \
                 -DMBEDTLS_PSA_CRYPTO_CONFIG_FILE=\\\"{PSACRYPTO_CONFIG}\\\" \' ' \
                 .format(CC=self.c_compiler,
                         MBEDCRYPTO_CONFIG=CONFIG_TFM_MEDIUM_MBEDCRYPTO_H,
                         PSACRYPTO_CONFIG=CONFIG_TFM_MEDIUM_PSA_CRYPTO_H)

        print("Unsupported combination of architecture: {} and configuration: {}"
              .format(self.arch, self.config))
        print("\nPlease use supported combination of architecture and configuration:")
        for comb in CodeSizeInfo.SupportedArchConfig:
            print(comb)
        print("\nFor your system, please use:")
        for comb in CodeSizeInfo.SupportedArchConfig:
            if "default" in comb and self.sys_arch not in comb:
                continue
            print(comb)
        sys.exit(1)

class SizeEntry: # pylint: disable=too-few-public-methods
    """Data Structure to only store information of code size."""
    def __init__(self, text, data, bss, dec):
        self.text = text
        self.data = data
        self.bss = bss
        self.total = dec # total <=> dec

class CodeSizeBase:
    """Code Size Base Class for size record saving and writing."""

    def __init__(self) -> None:
        """ Variable code_size is used to store size info for any revisions.
        code_size: (data format)
        {revision: {module: {file_name: SizeEntry,
                             etc ...
                            },
                    etc ...
                   },
         etc ...
        }
        """
        self.code_size = {} #type: typing.Dict[str, typing.Dict]

    def set_size_record(self, revision: str, mod: str, size_text: str) -> None:
        """Store size information for target revision and high-level module.

        size_text Format: text data bss dec hex filename
        """
        size_record = {}
        for line in size_text.splitlines()[1:]:
            data = line.split()
            size_record[data[5]] = SizeEntry(data[0], data[1], data[2], data[3])
        if revision in self.code_size:
            self.code_size[revision].update({mod: size_record})
        else:
            self.code_size[revision] = {mod: size_record}

    def read_size_record(self, revision: str, fname: str) -> None:
        """Read size information from csv file and write it into code_size.

        fname Format: filename text data bss dec
        """
        mod = ""
        size_record = {}
        with open(fname, 'r') as csv_file:
            for line in csv_file:
                data = line.strip().split()
                # check if we find the beginning of a module
                if data and data[0] in MBEDTLS_STATIC_LIB:
                    mod = data[0]
                    continue

                if mod:
                    size_record[data[0]] = \
                        SizeEntry(data[1], data[2], data[3], data[4])

                # check if we hit record for the end of a module
                m = re.match(r'.?TOTALS', line)
                if m:
                    if revision in self.code_size:
                        self.code_size[revision].update({mod: size_record})
                    else:
                        self.code_size[revision] = {mod: size_record}
                    mod = ""
                    size_record = {}

    def _size_reader_helper(
            self,
            revision: str,
            output: typing_util.Writable
    ) -> typing.Iterator[tuple]:
        """A helper function to peel code_size based on revision."""
        for mod, file_size in self.code_size[revision].items():
            output.write("\n" + mod + "\n")
            for fname, size_entry in file_size.items():
                yield mod, fname, size_entry

    def write_size_record(
            self,
            revision: str,
            output: typing_util.Writable
    ) -> None:
        """Write size information to a file.

        Writing Format: file_name text data bss total(dec)
        """
        output.write("{:<30} {:>7} {:>7} {:>7} {:>7}\n"
                     .format("filename", "text", "data", "bss", "total"))
        for _, fname, size_entry in self._size_reader_helper(revision, output):
            output.write("{:<30} {:>7} {:>7} {:>7} {:>7}\n"
                         .format(fname, size_entry.text, size_entry.data,\
                                 size_entry.bss, size_entry.total))

    def write_comparison(
            self,
            old_rev: str,
            new_rev: str,
            output: typing_util.Writable
    ) -> None:
        """Write comparison result into a file.

        Writing Format: file_name current(total) old(total) change(Byte) change_pct(%)
        """
        output.write("{:<30} {:>7} {:>7} {:>7} {:>7}\n"
                     .format("filename", "current", "old", "change", "change%"))
        for mod, fname, size_entry in self._size_reader_helper(new_rev, output):
            new_size = int(size_entry.total)
            # check if we have the file in old revision
            if fname in self.code_size[old_rev][mod]:
                old_size = int(self.code_size[old_rev][mod][fname].total)
                change = new_size - old_size
                if old_size != 0:
                    change_pct = change / old_size
                else:
                    change_pct = 0
                output.write("{:<30} {:>7} {:>7} {:>7} {:>7.2%}\n"
                             .format(fname, new_size, old_size, change, change_pct))
            else:
                output.write("{} {}\n".format(fname, new_size))


class CodeSizeComparison(CodeSizeBase):
    """Compare code size between two Git revisions."""

    def __init__(
            self,
            old_revision: str,
            new_revision: str,
            result_dir: str,
            code_size_info: CodeSizeInfo
    ) -> None:
        """
        old_revision: revision to compare against.
        new_revision:
        result_dir: directory for comparison result.
        code_size_info: an object containing information to build library.
        """
        super().__init__()
        self.repo_path = "."
        self.result_dir = os.path.abspath(result_dir)
        os.makedirs(self.result_dir, exist_ok=True)

        self.csv_dir = os.path.abspath("code_size_records/")
        os.makedirs(self.csv_dir, exist_ok=True)

        self.old_rev = old_revision
        self.new_rev = new_revision
        self.git_command = "git"
        self.tweak_config = code_size_info.tweak_config
        self.make_command = code_size_info.make_command
        self.fname_suffix = "-" + \
                            code_size_info.arch + "-" + \
                            code_size_info.config + "-" + \
                            code_size_info.c_compiler

    @staticmethod
    def validate_revision(revision: str) -> bytes:
        result = subprocess.check_output(["git", "rev-parse", "--verify",
                                          revision + "^{commit}"], shell=False)
        return result

    def _create_git_worktree(self, revision: str) -> str:
        """Make a separate worktree for revision.
        Do not modify the current worktree."""

        if revision == "current":
            print("Using current work directory")
            git_worktree_path = self.repo_path
        else:
            print("Creating git worktree for", revision)
            git_worktree_path = os.path.join(self.repo_path, "temp-" + revision)
            subprocess.check_output(
                [self.git_command, "worktree", "add", "--detach",
                 git_worktree_path, revision], cwd=self.repo_path,
                stderr=subprocess.STDOUT
            )

        return git_worktree_path

    @staticmethod
    def _tweak_config(
            config_dict: typing.Dict[str, frozenset],
            git_worktree_path: str,
            tweak: bool
    ) -> None:
        """Tweak configurations in the specified worktree."""
        for opt, config_set in config_dict.items():
            if not tweak:
                if opt == 'set':
                    opt = 'unset'
                else:
                    opt = 'set'
            for config in config_set:
                config_command = "./scripts/config.py " + opt + " " + config
                subprocess.check_output(
                    config_command, shell=True,
                    cwd=git_worktree_path, stderr=subprocess.STDOUT
                )

    def _build_libraries(self, git_worktree_path: str) -> None:
        """Build libraries in the specified worktree."""

        my_environment = os.environ.copy()
        if self.tweak_config:
            self._tweak_config(ARCH_CONFIG_DICT, git_worktree_path, True)
        try:
            subprocess.check_output(
                self.make_command, env=my_environment, shell=True,
                cwd=git_worktree_path, stderr=subprocess.STDOUT,
            )
        except subprocess.CalledProcessError as e:
            self._handle_called_process_error(e, git_worktree_path)
        if self.tweak_config:
            self._tweak_config(ARCH_CONFIG_DICT, git_worktree_path, False)

    def _gen_code_size_csv(self, revision: str, git_worktree_path: str) -> None:
        """Generate code size csv file."""

        if revision == "current":
            print("Measuring code size in current work directory")
        else:
            print("Measuring code size for", revision)

        for mod, st_lib in MBEDTLS_STATIC_LIB.items():
            try:
                result = subprocess.check_output(
                    ["size", st_lib, "-t"], cwd=git_worktree_path
                )
            except subprocess.CalledProcessError as e:
                self._handle_called_process_error(e, git_worktree_path)
            size_text = result.decode("utf-8")

            self.set_size_record(revision, mod, size_text)

        print("Generating code size csv for", revision)
        csv_file = open(os.path.join(self.csv_dir, revision +
                                     self.fname_suffix + ".csv"), "w")
        self.write_size_record(revision, csv_file)

    def _remove_worktree(self, git_worktree_path: str) -> None:
        """Remove temporary worktree."""
        if git_worktree_path != self.repo_path:
            print("Removing temporary worktree", git_worktree_path)
            subprocess.check_output(
                [self.git_command, "worktree", "remove", "--force",
                 git_worktree_path], cwd=self.repo_path,
                stderr=subprocess.STDOUT
            )

    def _get_code_size_for_rev(self, revision: str) -> None:
        """Generate code size csv file for the specified git revision."""

        # Check if the corresponding record exists
        csv_fname = revision + self.fname_suffix +  ".csv"
        if (revision != "current") and \
           os.path.exists(os.path.join(self.csv_dir, csv_fname)):
            print("Code size csv file for", revision, "already exists.")
            self.read_size_record(revision, os.path.join(self.csv_dir, csv_fname))
        else:
            git_worktree_path = self._create_git_worktree(revision)
            self._build_libraries(git_worktree_path)
            self._gen_code_size_csv(revision, git_worktree_path)
            self._remove_worktree(git_worktree_path)

    def _gen_code_size_comparison(self) -> int:
        """Generate results of the size changes between two revisions,
        old and new. Measured code size results of these two revisions
        must be available."""

        res_file = open(os.path.join(self.result_dir, "compare-" +
                                     self.old_rev + "-" + self.new_rev +
                                     self.fname_suffix +
                                     ".csv"), "w")

        print("\nGenerating comparison results between",\
                self.old_rev, "and", self.new_rev)
        self.write_comparison(self.old_rev, self.new_rev, res_file)

        return 0

    def get_comparision_results(self) -> int:
        """Compare size of library/*.o between self.old_rev and self.new_rev,
        and generate the result file."""
        build_tree.check_repo_path()
        self._get_code_size_for_rev(self.old_rev)
        self._get_code_size_for_rev(self.new_rev)
        return self._gen_code_size_comparison()

    def _handle_called_process_error(self, e: subprocess.CalledProcessError,
                                     git_worktree_path: str) -> None:
        """Handle a CalledProcessError and quit the program gracefully.
        Remove any extra worktrees so that the script may be called again."""

        # Tell the user what went wrong
        print("The following command: {} failed and exited with code {}"
              .format(e.cmd, e.returncode))
        print("Process output:\n {}".format(str(e.output, "utf-8")))

        # Quit gracefully by removing the existing worktree
        self._remove_worktree(git_worktree_path)
        sys.exit(-1)

def main():
    parser = argparse.ArgumentParser(description=(__doc__))
    group_required = parser.add_argument_group(
        'required arguments',
        'required arguments to parse for running ' + os.path.basename(__file__))
    group_required.add_argument(
        "-o", "--old-rev", type=str, required=True,
        help="old revision for comparison.")

    group_optional = parser.add_argument_group(
        'optional arguments',
        'optional arguments to parse for running ' + os.path.basename(__file__))
    group_optional.add_argument(
        "-r", "--result-dir", type=str, default="comparison",
        help="directory where comparison result is stored, \
              default is comparison")
    group_optional.add_argument(
        "-n", "--new-rev", type=str, default=None,
        help="new revision for comparison, default is the current work \
              directory, including uncommitted changes.")
    group_optional.add_argument(
        "-a", "--arch", type=str, default=detect_arch(),
        choices=list(map(lambda s: s.value, SupportedArch)),
        help="specify architecture for code size comparison, default is the\
              host architecture.")
    group_optional.add_argument(
        "-c", "--config", type=str, default=SupportedConfig.DEFAULT.value,
        choices=list(map(lambda s: s.value, SupportedConfig)),
        help="specify configuration type for code size comparison,\
              default is the current MbedTLS configuration.")
    group_optional.add_argument(
        "--cc", type=str, default=None, dest='c_compiler',
        help="specify C Compiler for code size comparison, default is None\
              which is default C Compiler in your system.")
    comp_args = parser.parse_args()

    if os.path.isfile(comp_args.result_dir):
        print("Error: {} is not a directory".format(comp_args.result_dir))
        parser.exit()

    validate_res = CodeSizeComparison.validate_revision(comp_args.old_rev)
    old_revision = validate_res.decode().replace("\n", "")

    if comp_args.new_rev is not None:
        validate_res = CodeSizeComparison.validate_revision(comp_args.new_rev)
        new_revision = validate_res.decode().replace("\n", "")
    else:
        new_revision = "current"

    code_size_info = CodeSizeInfo(comp_args.arch, comp_args.config,
                                  comp_args.c_compiler, detect_arch())
    print("Measure code size for architecture: {}, configuration: {}, C Compiler: {}\n"
          .format(code_size_info.arch, code_size_info.config,
                  code_size_info.c_compiler))
    result_dir = comp_args.result_dir
    size_compare = CodeSizeComparison(old_revision, new_revision, result_dir,
                                      code_size_info)
    return_code = size_compare.get_comparision_results()
    sys.exit(return_code)


if __name__ == "__main__":
    main()
