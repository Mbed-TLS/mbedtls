#!/usr/bin/env python3

# This file is part of Mbed TLS (https://tls.mbed.org)
# Copyright (c) 2018, Arm Limited, All Rights Reserved

"""
This script checks the current state of the source code for minor issues,
including incorrect file permissions, presence of tabs, non-Unix line endings,
trailing whitespace, and presence of UTF-8 BOM.
Note: requires python 3, must be run from Mbed TLS root.
"""

import os
import argparse
import logging
import codecs
import sys


class FileIssueTracker(object):
    """Base class for file-wide issue tracking.

    To implement a checker that processes a file as a whole, inherit from
    this class and implement `check_file_for_issue`.

    If a checker should omit certain files based on their names, override
    `should_check_file` accordingly.
    """

    def __init__(self, issue_collection):
        self.issue_collection = issue_collection

    @staticmethod
    def should_check_file(_filepath):
        """If a file issue tracker should omit certain files, override this
        method to return False on the files to omit."""
        return True

    def check_file_for_issue(self, filepath):
        """If `filepath` has issues, call `record_issue` on each instance
        of the issue."""
        raise NotImplementedError

    def record_issue(self, filepath, line_number, description):
        if filepath not in self.issue_collection:
            self.issue_collection[filepath] = []
        self.issue_collection[filepath].append((line_number, description))

class LineIssueTracker(object):
    """Class for line-by-line issue tracking.

    To implement a checker that processes files line by line, inherit from
    this class and implement `line_with_issue`.
    """

    def __init__(self, filepath):
        self.filepath = filepath

    @staticmethod
    def should_check_file(_basename):
        """If a line issue tracker should omit certain files, override this
        method to return False on the files to omit. Files are identified
        by their basename."""
        return True

    def issue_with_line(self, line):
        raise NotImplementedError

class ContentIssueTracker(FileIssueTracker):
    """Class for line-by-line issue tracking.
    """

    def __init__(self, issue_collection, trackers):
        super().__init__(issue_collection)
        self.trackers = trackers

    def check_file_for_issue(self, filepath):
        basename = os.path.basename(filepath)
        with open(filepath, "rb") as f:
            trackers = [tracker(filepath) for tracker in self.trackers
                        if tracker.should_check_file(basename)]
            for i, line in enumerate(iter(f.readline, b"")):
                for tracker in trackers:
                    if tracker.issue_with_line(line):
                        self.record_issue(filepath, i + 1, tracker.description)

class PermissionIssueTracker(FileIssueTracker):
    """Track files with bad permissions.

    Files that are not executable scripts must not be executable."""

    def check_file_for_issue(self, filepath):
        is_executable = os.access(filepath, os.X_OK)
        should_be_executable = filepath.endswith((".sh", ".pl", ".py"))
        if is_executable and not should_be_executable:
            self.record_issue(filepath, 0, "File should not be executable")
        elif not is_executable and should_be_executable:
            self.record_issue(filepath, 0, "File should be executable")


class EndOfFileNewlineIssueTracker(LineIssueTracker):
    """Track files that end with an incomplete line
    (no newline character at the end of the last line)."""

    description = "Missing newline at end of file"

    def issue_with_line(self, line):
        return not line.endswith(b"\n")


class Utf8BomIssueTracker(LineIssueTracker):
    """Track files that contain a line that starts with a UTF-8 BOM.
    Files should be ASCII or UTF-8. Valid UTF-8 does not contain BOM."""

    description = "UTF-8 BOM present"

    def issue_with_line(self, line):
        return line.startswith(codecs.BOM_UTF8)


class LineEndingIssueTracker(LineIssueTracker):
    """Track files with non-Unix line endings (i.e. files with CR)."""

    description = "Non-Unix line ending"

    def issue_with_line(self, line):
        return b"\r" in line


class TrailingWhitespaceIssueTracker(LineIssueTracker):
    """Track lines with trailing whitespace."""

    description = "Trailing whitespace"

    @staticmethod
    def should_check_file(filepath):
        return not filepath.endswith('.md')

    def issue_with_line(self, line):
        return line.rstrip(b"\r\n") != line.rstrip()


class TabIssueTracker(LineIssueTracker):
    """Track lines with tabs."""

    description = "Tab(s) present"

    @staticmethod
    def should_check_file(basename):
        return not ('Makefile' in basename or
                    basename == 'generate_visualc_files.pl')

    def issue_with_line(self, line):
        return b"\t" in line


class MergeArtifactIssueTracker(LineIssueTracker):
    """Track lines with merge artifacts.
    These are leftovers from a ``git merge`` that wasn't fully edited."""

    description = "Merge artifact"

    def issue_with_line(self, line):
        # Detect leftover git conflict markers.
        if line.startswith(b'<<<<<<< ') or line.startswith(b'>>>>>>> '):
            return True
        if line.startswith(b'||||||| '): # from merge.conflictStyle=diff3
            return True
        if line.rstrip(b'\r\n') == b'=======' and \
           not self.filepath.endswith('.md'):
            return True
        return False


class IntegrityChecker(object):
    """Sanity-check files under the current directory."""

    def __init__(self, log_file):
        """Instantiate the sanity checker.
        Check files under the current directory.
        Write a report of issues to log_file."""
        self.check_repo_path()
        self.logger = None
        self.setup_logger(log_file)
        self.files_to_check = (
            ".c", ".h", ".sh", ".pl", ".py", ".md", ".function", ".data",
            "Makefile", "CMakeLists.txt", "ChangeLog"
        )
        self.excluded_directories = ['.git', 'mbed-os']
        self.excluded_paths = list(map(os.path.normpath, [
            'cov-int',
            'examples',
        ]))
        self.issues = {}
        self.issues_to_check = [
            PermissionIssueTracker(self.issues),
            ContentIssueTracker(self.issues, [
                EndOfFileNewlineIssueTracker,
                Utf8BomIssueTracker,
                LineEndingIssueTracker,
                TrailingWhitespaceIssueTracker,
                TabIssueTracker,
                MergeArtifactIssueTracker,
            ])
        ]

    @staticmethod
    def check_repo_path():
        if not all(os.path.isdir(d) for d in ["include", "library", "tests"]):
            raise Exception("Must be run from Mbed TLS root")

    def setup_logger(self, log_file, level=logging.INFO):
        self.logger = logging.getLogger()
        self.logger.setLevel(level)
        if log_file:
            handler = logging.FileHandler(log_file)
            self.logger.addHandler(handler)
        else:
            console = logging.StreamHandler()
            self.logger.addHandler(console)

    def prune_branch(self, root, d):
        if d in self.excluded_directories:
            return True
        if os.path.normpath(os.path.join(root, d)) in self.excluded_paths:
            return True
        return False

    def check_files(self):
        for root, dirs, files in os.walk("."):
            dirs[:] = sorted(d for d in dirs if not self.prune_branch(root, d))
            for filename in sorted(files):
                filepath = os.path.join(root, filename)
                if not filepath.endswith(self.files_to_check):
                    continue
                for issue_to_check in self.issues_to_check:
                    basename = os.path.basename(filepath)
                    if issue_to_check.should_check_file(basename):
                        issue_to_check.check_file_for_issue(filepath)

    def output_issues(self):
        if not self.issues:
            return 0
        for filename in sorted(self.issues.keys()):
            for line, description in sorted(self.issues[filename]):
                self.logger.info("{}:{}: {}"
                                 .format(filename, line, description))
        return 1

def run_main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "-l", "--log_file", type=str, help="path to optional output log",
    )
    check_args = parser.parse_args()
    integrity_check = IntegrityChecker(check_args.log_file)
    integrity_check.check_files()
    return_code = integrity_check.output_issues()
    sys.exit(return_code)


if __name__ == "__main__":
    run_main()
