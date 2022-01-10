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

class CodeSizeComparison:
    """Compare code size between two Git revisions."""

    def __init__(self, old_revision, new_revision, result_dir,
                 config=None, symbols=False, buildtag=None):
        """
        old_revision: revision to compare against
        new_revision:
        result_dir: directory for comparision result
        """
        self.repo_path = "."
        self.result_dir = os.path.abspath(result_dir)
        os.makedirs(self.result_dir, exist_ok=True)

        self.csv_dir = os.path.abspath("code_size_records/")
        os.makedirs(self.csv_dir, exist_ok=True)

        self.old_rev = old_revision
        self.new_rev = new_revision
        self.git_command = "git"
        self.make_command = "make"
        self.symbols = symbols
        self.config = config
        self.buildtag = buildtag
        self.git_worktrees = []

    def __del__(self):
        for git_worktree_path in self.git_worktrees:
            self._remove_worktree(git_worktree_path)

    @staticmethod
    def check_repo_path():
        if not all(os.path.isdir(d) for d in ["include", "library", "tests"]):
            raise Exception("Must be run from Mbed TLS root")

    def get_file_stem(self, revision):
        if self.buildtag:
            return revision + "_" + self.buildtag
        else:
            return revision

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

            self.git_worktrees.append(git_worktree_path)

        return git_worktree_path

    def _build_libraries(self, git_worktree_path):
        """Build libraries in the specified worktree."""

        if self.config:
            subprocess.check_output(
                ["./scripts/config.py", self.config],
                cwd=git_worktree_path, stderr=subprocess.STDOUT
            )
        my_environment = os.environ.copy()
        subprocess.check_output(
            [self.make_command, "-j", "lib"], env=my_environment,
            cwd=git_worktree_path, stderr=subprocess.STDOUT,
        )

    def _gen_code_size_csv(self, revision, git_worktree_path):
        """Generate compilation-unit level code size csv file."""

        csv_fname = self.get_file_stem(revision) + ".csv"
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

    def _gen_code_size_csv_details(self, revision, git_worktree_path):
        """Generate symbol-level code size csv file"""

        csv_fname = self.get_file_stem(revision) + "_symbols.csv"
        if revision == "current":
            print("Measuring code size in current work directory.")
        else:
            print("Measuring code size for", revision)
        result = subprocess.check_output(
            ["nm library/*.a --size-sort"], cwd=git_worktree_path, shell=True
        )
        size_text = result.decode()
        csv_file = open(os.path.join(self.csv_dir, csv_fname), "w")

        cur_obj = None

        for line in size_text.splitlines()[1:]:

            # nm output groups symbols by object file and prefixes
            # the corresponding list with "OBJFILE.o"
            if len(line) > 3 and line[-3:] == ".o:":
                cur_obj = line[:-1]
            if cur_obj is None:
                continue

            # nm output format: size, type, name
            data = line.split()

            if len(data) < 3:
                continue

            csv_file.write("{size:<20} {symbol:<50} {objfile:<20} {ty}\n".format(
                objfile=cur_obj+",", symbol=data[2]+",", size=data[0]+",", ty=data[1]))

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
        csv_fname = self.get_file_stem(revision) + ".csv"

        if (revision != "current") and \
           os.path.exists(os.path.join(self.csv_dir, csv_fname)):
            print("Code size csv file for", revision, "already exists.")
        else:
            git_worktree_path = self._create_git_worktree(revision)
            self._build_libraries(git_worktree_path)
            self._gen_code_size_csv(revision, git_worktree_path)
            if self.symbols:
                self._gen_code_size_csv_details(revision, git_worktree_path)

    def compare_code_size(self):
        """Generate results of the size changes between two revisions,
        old and new. Measured code size results of these two revisions
        must be available."""

        old_stem = self.get_file_stem(self.old_rev)
        new_stem = self.get_file_stem(self.new_rev)

        old_file = open(os.path.join(self.csv_dir, old_stem + ".csv"), "r")
        new_file = open(os.path.join(self.csv_dir, new_stem + ".csv"), "r")
        res_file = open(os.path.join(self.result_dir, "compare-" + old_stem
                                     + "-" + new_stem + ".csv"), "w")

        res_file.write("file_name, this_size, old_size, change, change %\n")
        print("Generating comparision results.")

        old_ds = {}
        for line in old_file.readlines()[1:]:
            cols = line.split(", ")
            fname = cols[0]
            size = int(cols[1])
            if size != 0:
                old_ds[fname] = size

        new_ds = {}
        for line in new_file.readlines()[1:]:
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
        self.check_repo_path()
        self._get_code_size_for_rev(self.old_rev)
        self._get_code_size_for_rev(self.new_rev)
        return self.compare_code_size()

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
              directory, including uncommited changes."
    )
    parser.add_argument(
        "-s", "--symbols", default=False, action="store_true",
        help="emit code size statistics per symbol"
    )

    parser.add_argument(
        "-c", "--config", type=str, default=None,
        help="config to use for measurements; must be a valid argument to ./scripts/config.py"
    )

    parser.add_argument(
        "-t", "--tag", type=str, default=None,
        help="a string to attach to the emitted CSV file(s) indicating " +
        "the build type (e.g. CC, CFLAGS, Config)"
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

    result_dir = comp_args.result_dir
    size_compare = CodeSizeComparison(old_revision, new_revision, result_dir,
                                      config=comp_args.config,
                                      symbols=comp_args.symbols,
                                      buildtag=comp_args.tag)
    return_code = size_compare.get_comparision_results()
    sys.exit(return_code)


if __name__ == "__main__":
    main()
