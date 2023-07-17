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

from types import SimpleNamespace
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

class CodeSizeBuildInfo: # pylint: disable=too-few-public-methods
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
            size_version: SimpleNamespace,
            host_arch: str
    ) -> None:
        """
        size_version: SimpleNamespace containing info for code size measurement.
        size_version.arch: architecture to measure code size on.
        size_version.config: configuration type to measure code size with.
        host_arch: host architecture.
        """
        self.size_version = size_version
        self.host_arch = host_arch

    def infer_make_command(self) -> str:
        """Infer build command based on architecture and configuration."""

        if self.size_version.config == SupportedConfig.DEFAULT.value and \
            self.size_version.arch == self.host_arch:
            return 'make -j lib CFLAGS=\'-Os \' '
        elif self.size_version.arch == SupportedArch.ARMV8_M.value and \
             self.size_version.config == SupportedConfig.TFM_MEDIUM.value:
            return \
                 'make -j lib CC=armclang \
                  CFLAGS=\'--target=arm-arm-none-eabi -mcpu=cortex-m33 -Os \
                 -DMBEDTLS_CONFIG_FILE=\\\"' + CONFIG_TFM_MEDIUM_MBEDCRYPTO_H + '\\\" \
                 -DMBEDTLS_PSA_CRYPTO_CONFIG_FILE=\\\"' + CONFIG_TFM_MEDIUM_PSA_CRYPTO_H + '\\\" \''
        else:
            print("Unsupported combination of architecture: {} and configuration: {}"
                  .format(self.size_version.arch, self.size_version.config))
            print("\nPlease use supported combination of architecture and configuration:")
            for comb in CodeSizeBuildInfo.SupportedArchConfig:
                print(comb)
            print("\nFor your system, please use:")
            for comb in CodeSizeBuildInfo.SupportedArchConfig:
                if "default" in comb and self.host_arch not in comb:
                    continue
                print(comb)
            sys.exit(1)


class CodeSizeCalculator:
    """ A calculator to calculate code size of library objects based on
    Git revision and code size measurement tool.
    """

    def __init__(
            self,
            revision: str,
            make_cmd: str,
            measure_cmd: str
    ) -> None:
        """
        revision: Git revision.(E.g: commit)
        make_cmd: command to build objects in library.
        measure_cmd: command to measure code size for objects in library.
        """
        self.repo_path = "."
        self.git_command = "git"
        self.make_clean = 'make clean'

        self.revision = revision
        self.make_cmd = make_cmd
        self.measure_cmd = measure_cmd

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

    def _build_libraries(self, git_worktree_path: str) -> None:
        """Build libraries in the specified worktree."""

        my_environment = os.environ.copy()
        try:
            subprocess.check_output(
                self.make_clean, env=my_environment, shell=True,
                cwd=git_worktree_path, stderr=subprocess.STDOUT,
            )
            subprocess.check_output(
                self.make_cmd, env=my_environment, shell=True,
                cwd=git_worktree_path, stderr=subprocess.STDOUT,
            )
        except subprocess.CalledProcessError as e:
            self._handle_called_process_error(e, git_worktree_path)

    def _gen_raw_code_size(self, revision, git_worktree_path):
        """Calculate code size with measurement tool in UTF-8 encoding."""
        if revision == "current":
            print("Measuring code size in current work directory")
        else:
            print("Measuring code size for", revision)

        res = {}
        for mod, st_lib in MBEDTLS_STATIC_LIB.items():
            try:
                result = subprocess.check_output(
                    [self.measure_cmd + ' ' + st_lib], cwd=git_worktree_path,
                    shell=True, universal_newlines=True
                )
                res[mod] = result
            except subprocess.CalledProcessError as e:
                self._handle_called_process_error(e, git_worktree_path)

        return res

    def _remove_worktree(self, git_worktree_path: str) -> None:
        """Remove temporary worktree."""
        if git_worktree_path != self.repo_path:
            print("Removing temporary worktree", git_worktree_path)
            subprocess.check_output(
                [self.git_command, "worktree", "remove", "--force",
                 git_worktree_path], cwd=self.repo_path,
                stderr=subprocess.STDOUT
            )

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

    def cal_libraries_code_size(self) -> typing.Dict:
        """Calculate code size of libraries by measurement tool."""

        revision = self.revision
        git_worktree_path = self._create_git_worktree(revision)
        self._build_libraries(git_worktree_path)
        res = self._gen_raw_code_size(revision, git_worktree_path)
        self._remove_worktree(git_worktree_path)

        return res


class CodeSizeGenerator:
    """ A generator based on size measurement tool for library objects.

    This is an abstract class. To use it, derive a class that implements
    size_generator_write_record and size_generator_write_comparison methods,
    then call both of them with proper arguments.
    """
    def size_generator_write_record(
            self,
            revision: str,
            code_size_text: typing.Dict,
            output_file: str
    ) -> None:
        """Write size record into a file.

        revision: Git revision.(E.g: commit)
        code_size_text: text output (utf-8) from code size measurement tool.
        output_file: file which the code size record is written to.
        """
        raise NotImplementedError

    def size_generator_write_comparison(
            self,
            old_rev: str,
            new_rev: str,
            output_stream
    ) -> None:
        """Write a comparision result into a stream between two revisions.

        old_rev: old git revision to compared with.
        new_rev: new git revision to compared with.
        output_stream: stream which the code size record is written to.
                       (E.g: file / sys.stdout)
        """
        raise NotImplementedError


class CodeSizeGeneratorWithSize(CodeSizeGenerator):
    """Code Size Base Class for size record saving and writing."""

    class SizeEntry: # pylint: disable=too-few-public-methods
        """Data Structure to only store information of code size."""
        def __init__(self, text, data, bss, dec):
            self.text = text
            self.data = data
            self.bss = bss
            self.total = dec # total <=> dec

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
            size_record[data[5]] = CodeSizeGeneratorWithSize.SizeEntry(\
                    data[0], data[1], data[2], data[3])
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
                        CodeSizeGeneratorWithSize.SizeEntry(\
                        data[1], data[2], data[3], data[4])

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

    def size_generator_write_record(
            self,
            revision: str,
            code_size_text: typing.Dict,
            output_file: str
    ) -> None:
        """Write size record into a specified file based on Git revision and
        output from `size` tool."""
        for mod, size_text in code_size_text.items():
            self.set_size_record(revision, mod, size_text)

        print("Generating code size csv for", revision)
        output = open(output_file, "w")
        self.write_size_record(revision, output)

    def size_generator_write_comparison(
            self,
            old_rev: str,
            new_rev: str,
            output_stream
    ) -> None:
        """Write a comparision result into a stream between two revisions."""
        output = open(output_stream, "w")
        self.write_comparison(old_rev, new_rev, output)


class CodeSizeComparison:
    """Compare code size between two Git revisions."""

    def __init__(
            self,
            old_size_version: SimpleNamespace,
            new_size_version: SimpleNamespace,
            code_size_common: SimpleNamespace,
            result_dir: str,
    ) -> None:
        """
        old_revision: revision to compare against.
        new_revision:
        result_dir: directory for comparison result.
        """
        self.repo_path = "."
        self.result_dir = os.path.abspath(result_dir)
        os.makedirs(self.result_dir, exist_ok=True)

        self.csv_dir = os.path.abspath("code_size_records/")
        os.makedirs(self.csv_dir, exist_ok=True)

        self.old_size_version = old_size_version
        self.new_size_version = new_size_version
        self.code_size_common = code_size_common
        self.old_size_version.make_cmd = \
                CodeSizeBuildInfo(self.old_size_version,\
                    self.code_size_common.host_arch).infer_make_command()
        self.new_size_version.make_cmd = \
                CodeSizeBuildInfo(self.new_size_version,\
                    self.code_size_common.host_arch).infer_make_command()
        self.git_command = "git"
        self.make_clean = 'make clean'
        self.code_size_generator = self.__init_code_size_generator__(\
                self.code_size_common.measure_cmd)

    @staticmethod
    def __init_code_size_generator__(measure_cmd):
        if re.match(r'size', measure_cmd.strip()):
            return CodeSizeGeneratorWithSize()
        else:
            print("Error: unsupported tool:", measure_cmd.strip().split(' ')[0])
            sys.exit(1)


    def cal_code_size(self, size_version: SimpleNamespace):
        """Calculate code size of library objects in a UTF-8 encoding"""

        return CodeSizeCalculator(size_version.revision, size_version.make_cmd,\
                self.code_size_common.measure_cmd).cal_libraries_code_size()

    def gen_file_name(self, old_size_version, new_size_version=None):
        if new_size_version:
            return '{}-{}-{}-{}-{}-{}-{}.csv'\
                    .format(old_size_version.revision[:7],
                            old_size_version.arch, old_size_version.config,
                            new_size_version.revision[:7],
                            new_size_version.arch, new_size_version.config,
                            self.code_size_common.measure_cmd.strip().split(' ')[0])
        else:
            return '{}-{}-{}-{}.csv'\
                    .format(old_size_version.revision[:7],
                            old_size_version.arch, old_size_version.config,
                            self.code_size_common.measure_cmd.strip().split(' ')[0])

    def gen_code_size_report(self, size_version: SimpleNamespace):
        """Generate code size record and write it into a file."""

        output_file = os.path.join(self.csv_dir, self.gen_file_name(size_version))
        # Check if the corresponding record exists
        if (size_version.revision != "current") and os.path.exists(output_file):
            print("Code size csv file for", size_version.revision, "already exists.")
            self.code_size_generator.read_size_record(size_version.revision, output_file)
        else:
            self.code_size_generator.size_generator_write_record(\
                    size_version.revision, self.cal_code_size(size_version),
                    output_file)

    def gen_code_size_comparison(self) -> int:
        """Generate results of code size changes between two revisions,
        old and new. Measured code size results of these two revisions
        must be available."""

        output_file = os.path.join(self.result_dir,\
                self.gen_file_name(self.old_size_version, self.new_size_version))

        print("\nGenerating comparison results between",\
                self.old_size_version.revision, "and", self.new_size_version.revision)
        self.code_size_generator.size_generator_write_comparison(\
                self.old_size_version.revision, self.new_size_version.revision,\
                output_file)
        return 0

    def get_comparision_results(self) -> int:
        """Compare size of library/*.o between self.old_rev and self.new_rev,
        and generate the result file."""
        build_tree.check_repo_path()
        self.gen_code_size_report(self.old_size_version)
        self.gen_code_size_report(self.new_size_version)
        return self.gen_code_size_comparison()


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
    comp_args = parser.parse_args()

    if os.path.isfile(comp_args.result_dir):
        print("Error: {} is not a directory".format(comp_args.result_dir))
        parser.exit()

    validate_res = CodeSizeCalculator.validate_revision(comp_args.old_rev)
    old_revision = validate_res.decode().replace("\n", "")

    if comp_args.new_rev is not None:
        validate_res = CodeSizeCalculator.validate_revision(comp_args.new_rev)
        new_revision = validate_res.decode().replace("\n", "")
    else:
        new_revision = "current"

    old_size_version = SimpleNamespace(
        version="old",
        revision=old_revision,
        config=comp_args.config,
        arch=comp_args.arch,
        make_cmd='',
    )
    new_size_version = SimpleNamespace(
        version="new",
        revision=new_revision,
        config=comp_args.config,
        arch=comp_args.arch,
        make_cmd='',
    )
    code_size_common = SimpleNamespace(
        host_arch=detect_arch(),
        measure_cmd='size -t',
    )

    size_compare = CodeSizeComparison(old_size_version, new_size_version,\
            code_size_common, comp_args.result_dir)
    return_code = size_compare.get_comparision_results()
    sys.exit(return_code)


if __name__ == "__main__":
    main()
