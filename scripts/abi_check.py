#!/usr/bin/env python3
"""
This file is part of Mbed TLS (https://tls.mbed.org)

Copyright (c) 2018, Arm Limited, All Rights Reserved

Purpose

This script is a small wrapper around the abi-compliance-checker and
abi-dumper tools, applying them to compare the ABI and API of the library
files from two different Git revisions within an Mbed TLS repository.
The results of the comparison are either formatted as HTML and stored at
a configurable location, or are given as a brief list of problems.
Returns 0 on success, 1 on ABI/API non-compliance, and 2 if there is an error
while running the script. Note: must be run from Mbed TLS root.
"""

import os
import sys
import traceback
import shutil
import subprocess
import argparse
import logging
import tempfile
import fnmatch
from types import SimpleNamespace

import xml.etree.ElementTree as ET


class AbiChecker(object):
    """API and ABI checker."""

    def __init__(self, old_version, new_version, configuration):
        """Instantiate the API/ABI checker.

        old_version: RepoVersion containing details to compare against
        new_version: RepoVersion containing details to check
        configuration.report_dir: directory for output files
        configuration.keep_all_reports: if false, delete old reports
        configuration.brief: if true, output shorter report to stdout
        configuration.skip_file: path to file containing symbols and types to skip
        """
        self.repo_path = "."
        self.log = None
        self.verbose = configuration.verbose
        self._setup_logger()
        self.report_dir = os.path.abspath(configuration.report_dir)
        self.keep_all_reports = configuration.keep_all_reports
        self.can_remove_report_dir = not (os.path.exists(self.report_dir) or
                                          self.keep_all_reports)
        self.old_version = old_version
        self.new_version = new_version
        self.skip_file = configuration.skip_file
        self.brief = configuration.brief
        self.git_command = "git"
        self.make_command = "make"

    @staticmethod
    def check_repo_path():
        current_dir = os.path.realpath('.')
        root_dir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
        if current_dir != root_dir:
            raise Exception("Must be run from Mbed TLS root")

    def _setup_logger(self):
        self.log = logging.getLogger()
        if self.verbose:
            self.log.setLevel(logging.DEBUG)
        else:
            self.log.setLevel(logging.INFO)
        self.log.addHandler(logging.StreamHandler())

    @staticmethod
    def check_abi_tools_are_installed():
        for command in ["abi-dumper", "abi-compliance-checker"]:
            if not shutil.which(command):
                raise Exception("{} not installed, aborting".format(command))

    def _get_clean_worktree_for_git_revision(self, version):
        """Make a separate worktree with version.revision checked out.
        Do not modify the current worktree."""
        git_worktree_path = tempfile.mkdtemp()
        if version.repository:
            self.log.debug(
                "Checking out git worktree for revision {} from {}".format(
                    version.revision, version.repository
                )
            )
            fetch_output = subprocess.check_output(
                [self.git_command, "fetch",
                 version.repository, version.revision],
                cwd=self.repo_path,
                stderr=subprocess.STDOUT
            )
            self.log.debug(fetch_output.decode("utf-8"))
            worktree_rev = "FETCH_HEAD"
        else:
            self.log.debug("Checking out git worktree for revision {}".format(
                version.revision
            ))
            worktree_rev = version.revision
        worktree_output = subprocess.check_output(
            [self.git_command, "worktree", "add", "--detach",
             git_worktree_path, worktree_rev],
            cwd=self.repo_path,
            stderr=subprocess.STDOUT
        )
        self.log.debug(worktree_output.decode("utf-8"))
        return git_worktree_path

    def _update_git_submodules(self, git_worktree_path, version):
        """If the crypto submodule is present, initialize it.
        if version.crypto_revision exists, update it to that revision,
        otherwise update it to the default revision"""
        update_output = subprocess.check_output(
            [self.git_command, "submodule", "update", "--init", '--recursive'],
            cwd=git_worktree_path,
            stderr=subprocess.STDOUT
        )
        self.log.debug(update_output.decode("utf-8"))
        if not (os.path.exists(os.path.join(git_worktree_path, "crypto"))
                and version.crypto_revision):
            return

        if version.crypto_repository:
            fetch_output = subprocess.check_output(
                [self.git_command, "fetch", version.crypto_repository,
                 version.crypto_revision],
                cwd=os.path.join(git_worktree_path, "crypto"),
                stderr=subprocess.STDOUT
            )
            self.log.debug(fetch_output.decode("utf-8"))
            crypto_rev = "FETCH_HEAD"
        else:
            crypto_rev = version.crypto_revision

        checkout_output = subprocess.check_output(
            [self.git_command, "checkout", crypto_rev],
            cwd=os.path.join(git_worktree_path, "crypto"),
            stderr=subprocess.STDOUT
        )
        self.log.debug(checkout_output.decode("utf-8"))

    def _build_shared_libraries(self, git_worktree_path, version):
        """Build the shared libraries in the specified worktree."""
        my_environment = os.environ.copy()
        my_environment["CFLAGS"] = "-g -Og"
        my_environment["SHARED"] = "1"
        if os.path.exists(os.path.join(git_worktree_path, "crypto")):
            my_environment["USE_CRYPTO_SUBMODULE"] = "1"
        make_output = subprocess.check_output(
            [self.make_command, "lib"],
            env=my_environment,
            cwd=git_worktree_path,
            stderr=subprocess.STDOUT
        )
        self.log.debug(make_output.decode("utf-8"))
        for root, _dirs, files in os.walk(git_worktree_path):
            for file in fnmatch.filter(files, "*.so"):
                version.modules[os.path.splitext(file)[0]] = (
                    os.path.join(root, file)
                )

    def _get_abi_dumps_from_shared_libraries(self, version):
        """Generate the ABI dumps for the specified git revision.
        The shared libraries must have been built and the module paths
        present in version.modules."""
        for mbed_module, module_path in version.modules.items():
            output_path = os.path.join(
                self.report_dir, "{}-{}-{}.dump".format(
                    mbed_module, version.revision, version.version
                )
            )
            abi_dump_command = [
                "abi-dumper",
                module_path,
                "-o", output_path,
                "-lver", version.revision
            ]
            abi_dump_output = subprocess.check_output(
                abi_dump_command,
                stderr=subprocess.STDOUT
            )
            self.log.debug(abi_dump_output.decode("utf-8"))
            version.abi_dumps[mbed_module] = output_path

    def _cleanup_worktree(self, git_worktree_path):
        """Remove the specified git worktree."""
        shutil.rmtree(git_worktree_path)
        worktree_output = subprocess.check_output(
            [self.git_command, "worktree", "prune"],
            cwd=self.repo_path,
            stderr=subprocess.STDOUT
        )
        self.log.debug(worktree_output.decode("utf-8"))

    def _get_abi_dump_for_ref(self, version):
        """Generate the ABI dumps for the specified git revision."""
        git_worktree_path = self._get_clean_worktree_for_git_revision(version)
        self._update_git_submodules(git_worktree_path, version)
        self._build_shared_libraries(git_worktree_path, version)
        self._get_abi_dumps_from_shared_libraries(version)
        self._cleanup_worktree(git_worktree_path)

    def _remove_children_with_tag(self, parent, tag):
        children = parent.getchildren()
        for child in children:
            if child.tag == tag:
                parent.remove(child)
            else:
                self._remove_children_with_tag(child, tag)

    def _remove_extra_detail_from_report(self, report_root):
        for tag in ['test_info', 'test_results', 'problem_summary',
                    'added_symbols', 'affected']:
            self._remove_children_with_tag(report_root, tag)

        for report in report_root:
            for problems in report.getchildren()[:]:
                if not problems.getchildren():
                    report.remove(problems)

    def get_abi_compatibility_report(self):
        """Generate a report of the differences between the reference ABI
        and the new ABI. ABI dumps from self.old_version and self.new_version
        must be available."""
        compatibility_report = ""
        compliance_return_code = 0
        shared_modules = list(set(self.old_version.modules.keys()) &
                              set(self.new_version.modules.keys()))
        for mbed_module in shared_modules:
            output_path = os.path.join(
                self.report_dir, "{}-{}-{}.html".format(
                    mbed_module, self.old_version.revision,
                    self.new_version.revision
                )
            )
            abi_compliance_command = [
                "abi-compliance-checker",
                "-l", mbed_module,
                "-old", self.old_version.abi_dumps[mbed_module],
                "-new", self.new_version.abi_dumps[mbed_module],
                "-strict",
                "-report-path", output_path,
            ]
            if self.skip_file:
                abi_compliance_command += ["-skip-symbols", self.skip_file,
                                           "-skip-types", self.skip_file]
            if self.brief:
                abi_compliance_command += ["-report-format", "xml",
                                           "-stdout"]
            try:
                subprocess.check_output(
                    abi_compliance_command,
                    stderr=subprocess.STDOUT
                )
            except subprocess.CalledProcessError as err:
                if err.returncode == 1:
                    compliance_return_code = 1
                    if self.brief:
                        self.log.info(
                            "Compatibility issues found for {}".format(mbed_module)
                        )
                        report_root = ET.fromstring(err.output.decode("utf-8"))
                        self._remove_extra_detail_from_report(report_root)
                        self.log.info(ET.tostring(report_root).decode("utf-8"))
                    else:
                        self.can_remove_report_dir = False
                        compatibility_report += (
                            "Compatibility issues found for {}, "
                            "for details see {}\n".format(mbed_module, output_path)
                        )
                else:
                    raise err
            else:
                compatibility_report += (
                    "No compatibility issues for {}\n".format(mbed_module)
                )
                if not (self.keep_all_reports or self.brief):
                    os.remove(output_path)
        for version in [self.old_version, self.new_version]:
            for mbed_module, mbed_module_dump in version.abi_dumps.items():
                os.remove(mbed_module_dump)
        if self.can_remove_report_dir:
            os.rmdir(self.report_dir)
        self.log.info(compatibility_report)
        return compliance_return_code

    def check_for_abi_changes(self):
        """Generate a report of ABI differences
        between self.old_rev and self.new_rev."""
        self.check_repo_path()
        self.check_abi_tools_are_installed()
        self._get_abi_dump_for_ref(self.old_version)
        self._get_abi_dump_for_ref(self.new_version)
        return self.get_abi_compatibility_report()


def run_main():
    try:
        parser = argparse.ArgumentParser(
            description=(
                """This script is a small wrapper around the
                abi-compliance-checker and abi-dumper tools, applying them
                to compare the ABI and API of the library files from two
                different Git revisions within an Mbed TLS repository.
                The results of the comparison are either formatted as HTML and
                stored at a configurable location, or are given as a brief list
                of problems. Returns 0 on success, 1 on ABI/API non-compliance,
                and 2 if there is an error while running the script.
                Note: must be run from Mbed TLS root."""
            )
        )
        parser.add_argument(
            "-v", "--verbose", action="store_true",
            help="set verbosity level",
        )
        parser.add_argument(
            "-r", "--report-dir", type=str, default="reports",
            help="directory where reports are stored, default is reports",
        )
        parser.add_argument(
            "-k", "--keep-all-reports", action="store_true",
            help="keep all reports, even if there are no compatibility issues",
        )
        parser.add_argument(
            "-o", "--old-rev", type=str, help="revision for old version.",
            required=True,
        )
        parser.add_argument(
            "-or", "--old-repo", type=str, help="repository for old version."
        )
        parser.add_argument(
            "-oc", "--old-crypto-rev", type=str,
            help="revision for old crypto submodule."
        )
        parser.add_argument(
            "-ocr", "--old-crypto-repo", type=str,
            help="repository for old crypto submodule."
        )
        parser.add_argument(
            "-n", "--new-rev", type=str, help="revision for new version",
            required=True,
        )
        parser.add_argument(
            "-nr", "--new-repo", type=str, help="repository for new version."
        )
        parser.add_argument(
            "-nc", "--new-crypto-rev", type=str,
            help="revision for new crypto version"
        )
        parser.add_argument(
            "-ncr", "--new-crypto-repo", type=str,
            help="repository for new crypto submodule."
        )
        parser.add_argument(
            "-s", "--skip-file", type=str,
            help="path to file containing symbols and types to skip"
        )
        parser.add_argument(
            "-b", "--brief", action="store_true",
            help="output only the list of issues to stdout, instead of a full report",
        )
        abi_args = parser.parse_args()
        if os.path.isfile(abi_args.report_dir):
            print("Error: {} is not a directory".format(abi_args.report_dir))
            parser.exit()
        old_version = SimpleNamespace(
            version="old",
            repository=abi_args.old_repo,
            revision=abi_args.old_rev,
            crypto_repository=abi_args.old_crypto_repo,
            crypto_revision=abi_args.old_crypto_rev,
            abi_dumps={},
            modules={}
        )
        new_version = SimpleNamespace(
            version="new",
            repository=abi_args.new_repo,
            revision=abi_args.new_rev,
            crypto_repository=abi_args.new_crypto_repo,
            crypto_revision=abi_args.new_crypto_rev,
            abi_dumps={},
            modules={}
        )
        configuration = SimpleNamespace(
            verbose=abi_args.verbose,
            report_dir=abi_args.report_dir,
            keep_all_reports=abi_args.keep_all_reports,
            brief=abi_args.brief,
            skip_file=abi_args.skip_file
        )
        abi_check = AbiChecker(old_version, new_version, configuration)
        return_code = abi_check.check_for_abi_changes()
        sys.exit(return_code)
    except Exception: # pylint: disable=broad-except
        # Print the backtrace and exit explicitly so as to exit with
        # status 2, not 1.
        traceback.print_exc()
        sys.exit(2)


if __name__ == "__main__":
    run_main()
