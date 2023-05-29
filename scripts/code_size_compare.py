#!/usr/bin/env python3

"""
Purpose

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
import subprocess
import sys
from enum import Enum

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

class CodeSizeInfo: # pylint: disable=too-few-public-methods
    """Gather information used to measure code size.

    It collects information about architecture, configuration in order to
    infer build command for code size measurement.
    """

    def __init__(self, arch: str, config: str) -> None:
        """
        arch: architecture to measure code size on.
        config: configuration type to measure code size with.
        make_command: command to build library (Inferred from arch and config).
        """
        self.arch = arch
        self.config = config
        self.make_command = self.set_make_command()

    def set_make_command(self) -> str:
        """Infer build command based on architecture and configuration."""

        if self.config == SupportedConfig.DEFAULT.value:
            return 'make -j lib CFLAGS=\'-Os \' '
        elif self.arch == SupportedArch.ARMV8_M.value and \
             self.config == SupportedConfig.TFM_MEDIUM.value:
            return \
                 'make -j lib CC=armclang \
                  CFLAGS=\'--target=arm-arm-none-eabi -mcpu=cortex-m33 -Os \
                 -DMBEDTLS_CONFIG_FILE=\\\"' + CONFIG_TFM_MEDIUM_MBEDCRYPTO_H + '\\\" \
                 -DMBEDTLS_PSA_CRYPTO_CONFIG_FILE=\\\"' + CONFIG_TFM_MEDIUM_PSA_CRYPTO_H + '\\\" \''
        else:
            print("Unsupported architecture: {} and configurations: {}"
                  .format(self.arch, self.config))
            sys.exit(1)


class CodeSizeComparison:
    """Compare code size between two Git revisions."""

    def __init__(self, old_revision, new_revision, result_dir, code_size_info):
        """
        old_revision: revision to compare against.
        new_revision:
        result_dir: directory for comparison result.
        code_size_info: an object containing information to build library.
        """
        self.repo_path = "."
        self.result_dir = os.path.abspath(result_dir)
        os.makedirs(self.result_dir, exist_ok=True)

        self.csv_dir = os.path.abspath("code_size_records/")
        os.makedirs(self.csv_dir, exist_ok=True)

        self.old_rev = old_revision
        self.new_rev = new_revision
        self.git_command = "git"
        self.make_command = code_size_info.make_command
        self.fname_suffix = "-" + code_size_info.arch + "-" +\
                            code_size_info.config

    @staticmethod
    def validate_revision(revision):
        result = subprocess.check_output(["git", "rev-parse", "--verify",
                                          revision + "^{commit}"], shell=False)
        return result

    def _create_git_worktree(self, revision):
        """Make a separate worktree for revision.
        Do not modify the current worktree."""

        if revision == "current":
            print("Using current work directory.")
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

    def _build_libraries(self, git_worktree_path):
        """Build libraries in the specified worktree."""

        my_environment = os.environ.copy()
        try:
            subprocess.check_output(
                self.make_command, env=my_environment, shell=True,
                cwd=git_worktree_path, stderr=subprocess.STDOUT,
            )
        except subprocess.CalledProcessError as e:
            self._handle_called_process_error(e, git_worktree_path)

    def _gen_code_size_csv(self, revision, git_worktree_path):
        """Generate code size csv file."""

        csv_fname = revision + self.fname_suffix + ".csv"
        if revision == "current":
            print("Measuring code size in current work directory.")
        else:
            print("Measuring code size for", revision)
        result = subprocess.check_output(
            ["size library/*.o"], cwd=git_worktree_path, shell=True
        )
        size_text = result.decode()
        csv_file = open(os.path.join(self.csv_dir, csv_fname), "w")
        for line in size_text.splitlines()[1:]:
            data = line.split()
            csv_file.write("{}, {}\n".format(data[5], data[3]))

    def _remove_worktree(self, git_worktree_path):
        """Remove temporary worktree."""
        if git_worktree_path != self.repo_path:
            print("Removing temporary worktree", git_worktree_path)
            subprocess.check_output(
                [self.git_command, "worktree", "remove", "--force",
                 git_worktree_path], cwd=self.repo_path,
                stderr=subprocess.STDOUT
            )

    def _get_code_size_for_rev(self, revision):
        """Generate code size csv file for the specified git revision."""

        # Check if the corresponding record exists
        csv_fname = revision + self.fname_suffix +  ".csv"
        if (revision != "current") and \
           os.path.exists(os.path.join(self.csv_dir, csv_fname)):
            print("Code size csv file for", revision, "already exists.")
        else:
            git_worktree_path = self._create_git_worktree(revision)
            self._build_libraries(git_worktree_path)
            self._gen_code_size_csv(revision, git_worktree_path)
            self._remove_worktree(git_worktree_path)

    def compare_code_size(self):
        """Generate results of the size changes between two revisions,
        old and new. Measured code size results of these two revisions
        must be available."""

        old_file = open(os.path.join(self.csv_dir, self.old_rev +
                                     self.fname_suffix + ".csv"), "r")
        new_file = open(os.path.join(self.csv_dir, self.new_rev +
                                     self.fname_suffix + ".csv"), "r")
        res_file = open(os.path.join(self.result_dir, "compare-" +
                                     self.old_rev + "-" + self.new_rev +
                                     self.fname_suffix +
                                     ".csv"), "w")

        res_file.write("file_name, this_size, old_size, change, change %\n")
        print("Generating comparison results.")

        old_ds = {}
        for line in old_file.readlines():
            cols = line.split(", ")
            fname = cols[0]
            size = int(cols[1])
            if size != 0:
                old_ds[fname] = size

        new_ds = {}
        for line in new_file.readlines():
            cols = line.split(", ")
            fname = cols[0]
            size = int(cols[1])
            new_ds[fname] = size

        for fname in new_ds:
            this_size = new_ds[fname]
            if fname in old_ds:
                old_size = old_ds[fname]
                change = this_size - old_size
                change_pct = change / old_size
                res_file.write("{}, {}, {}, {}, {:.2%}\n".format(fname, \
                               this_size, old_size, change, float(change_pct)))
            else:
                res_file.write("{}, {}\n".format(fname, this_size))
        return 0

    def get_comparision_results(self):
        """Compare size of library/*.o between self.old_rev and self.new_rev,
        and generate the result file."""
        build_tree.check_repo_path()
        self._get_code_size_for_rev(self.old_rev)
        self._get_code_size_for_rev(self.new_rev)
        return self.compare_code_size()

    def _handle_called_process_error(self, e: subprocess.CalledProcessError,
                                     git_worktree_path):
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
    parser = argparse.ArgumentParser(
        description=(
            """This script is for comparing the size of the library files
            from two different Git revisions within an Mbed TLS repository.
            The results of the comparison is formatted as csv, and stored at
            a configurable location.
            Note: must be run from Mbed TLS root."""
        )
    )
    parser.add_argument(
        "-r", "--result-dir", type=str, default="comparison",
        help="directory where comparison result is stored, \
              default is comparison",
    )
    parser.add_argument(
        "-o", "--old-rev", type=str, help="old revision for comparison.",
        required=True,
    )
    parser.add_argument(
        "-n", "--new-rev", type=str, default=None,
        help="new revision for comparison, default is the current work \
              directory, including uncommitted changes."
    )
    parser.add_argument(
        "-a", "--arch", type=str, default=detect_arch(),
        choices=list(map(lambda s: s.value, SupportedArch)),
        help="specify architecture for code size comparison, default is the\
              host architecture."
    )
    parser.add_argument(
        "-c", "--config", type=str, default=SupportedConfig.DEFAULT.value,
        choices=list(map(lambda s: s.value, SupportedConfig)),
        help="specify configuration type for code size comparison,\
              default is the current MbedTLS configuration."
    )
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

    code_size_info = CodeSizeInfo(comp_args.arch, comp_args.config)
    print("Measure code size for architecture: {}, configuration: {}"
          .format(code_size_info.arch, code_size_info.config))
    result_dir = comp_args.result_dir
    size_compare = CodeSizeComparison(old_revision, new_revision, result_dir,
                                      code_size_info)
    return_code = size_compare.get_comparision_results()
    sys.exit(return_code)


if __name__ == "__main__":
    main()
