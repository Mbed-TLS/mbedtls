#!/usr/bin/env python3

"""Archive the contents of the specified files for the specified Git revisions.

Run this script from a clean Git worktree.
This script runs `make FILE` to generate the desired files.
The outputs are stored in a subdirectory named for each commit hash.
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
import shutil
import subprocess
from typing import List, Optional


class UncommittedChangesException(Exception):
    "You have uncommitted changes. Please stash or commit them."
    pass


class Archiver:
    """Archive the contents of some files for some Git revisions."""

    def __init__(
            self,
            build_dir: Optional[str] = None,
            output_dir: Optional[str] = None,
            run_after: Optional[str] = None,
            run_before: Optional[str] = None,
    ) -> None:
        """Configure an archiver for generated files.

        `build_dir`: directory where ``make`` will be run.
        `output_dir`: parent directory for the per-revision directories.
        `run_before`: shell command to run before ``make``.
        `run_after`: shell command to run after ``make``.
        """
        self.build_dir = build_dir if build_dir is not None else os.curdir
        self.output_dir = output_dir if output_dir is not None else os.curdir
        self.run_before = run_before
        self.run_after = run_after
        self.prepare()

    def prepare(self) -> None:
        """Prepare the working directory."""
        try:
            subprocess.check_call(['git', 'diff', '--quiet'])
        except subprocess.CalledProcessError:
            raise UncommittedChangesException()
        self.initial_revision = subprocess.check_output(
            ['git', 'rev-parse', '--abbrev-ref', 'HEAD']
        ).decode('ascii').strip()

    def done(self) -> None:
        """Restore the working directory."""
        subprocess.check_call(['git', 'checkout', self.initial_revision])

    def archive_revision(self, revision: str, files: List[str]) -> None:
        """Archive generated files for a given revision.

        `revision`: Git revision to check out.
        `files`: list of files to archive.
        """
        subprocess.check_call(['git', 'checkout', revision])
        if self.run_before:
            subprocess.check_call(self.run_before, shell=True)
        subprocess.check_call(['make'] + files,
                              cwd=self.build_dir)
        for filename in files:
            target_dir = os.path.join(self.output_dir,
                                      revision,
                                      os.path.dirname(filename))
            os.makedirs(target_dir, exist_ok=True)
            shutil.copy2(filename, target_dir)
        if self.run_after:
            subprocess.check_call(self.run_after, shell=True)

    def archive_revisions(self, revision_range: str, files: List[str]) -> None:
        """Archive generated files for a given revision range.

        `revision`: Git revision range to check out.
        `files`: list of files to archive.
        """
        self.prepare()
        try:
            revisions = subprocess.check_output(
                ['git', 'log', '--format=%H', revision_range]
            ).decode('ascii').split()
            for revision in revisions:
                self.archive_revision(revision, files)
        finally:
            self.done()


def main() -> None:
    """Command line entry point."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', '-b', metavar='DIR',
                        help='Run `make` in DIR')
    parser.add_argument('--output-dir', '-o', metavar='DIR',
                        help='Put output directories under DIR')
    parser.add_argument('--run-after', '-R', metavar='CMD',
                        help='Shell command to run after each build')
    parser.add_argument('--run-before', '-r', metavar='CMD',
                        help='Shell command to run before each build')
    parser.add_argument('revisions', metavar='REVISIONS',
                        help='Comma-separated of Git revisions (see gitrevisions(7))')
    parser.add_argument('files', metavar='FILE', nargs='*',
                        help='File to archive')
    options = parser.parse_args()
    revision_ranges = options.revisions.split(',')
    del options.revisions
    files = options.files
    del options.files
    archiver = Archiver(**vars(options))
    for revision_range in revision_ranges:
        archiver.archive_revisions(revision_range, files)

if __name__ == '__main__':
    main()
