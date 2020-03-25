#!/usr/bin/env python3

"""Assemble Mbed Crypto change log entries into the change log file.

Add changelog entries to the first level-2 section.
Create a new level-2 section for unreleased changes if needed.
Remove the input files unless --keep-entries is specified.
"""

# Copyright (C) 2019, Arm Limited, All Rights Reserved
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
#
# This file is part of Mbed Crypto (https://tls.mbed.org)

import argparse
from collections import OrderedDict
import datetime
import functools
import glob
import os
import re
import subprocess
import sys

class InputFormatError(Exception):
    def __init__(self, filename, line_number, message, *args, **kwargs):
        message = '{}:{}: {}'.format(filename, line_number,
                                     message.format(*args, **kwargs))
        super().__init__(message)

class LostContent(Exception):
    def __init__(self, filename, line):
        message = ('Lost content from {}: "{}"'.format(filename, line))
        super().__init__(message)

STANDARD_SECTIONS = (
    b'Interface changes',
    b'Default behavior changes',
    b'Requirement changes',
    b'New deprecations',
    b'Removals',
    b'New features',
    b'Security',
    b'Bug fixes',
    b'Performance improvements',
    b'Other changes',
)

class ChangeLog:
    """An Mbed Crypto changelog.

    A changelog is a file in Markdown format. Each level 2 section title
    starts a version, and versions are sorted in reverse chronological
    order. Lines with a level 2 section title must start with '##'.

    Within a version, there are multiple sections, each devoted to a kind
    of change: bug fix, feature request, etc. Section titles should match
    entries in STANDARD_SECTIONS exactly.

    Within each section, each separate change should be on a line starting
    with a '*' bullet. There may be blank lines surrounding titles, but
    there should not be any blank line inside a section.
    """

    _title_re = re.compile(br'#*')
    def title_level(self, line):
        """Determine whether the line is a title.

        Return (level, content) where level is the Markdown section level
        (1 for '#', 2 for '##', etc.) and content is the section title
        without leading or trailing whitespace. For a non-title line,
        the level is 0.
        """
        level = re.match(self._title_re, line).end()
        return level, line[level:].strip()

    # Only accept dotted version numbers (e.g. "3.1", not "3").
    # Refuse ".x" in a version number where x is a letter: this indicates
    # a version that is not yet released. Something like "3.1a" is accepted.
    _version_number_re = re.compile(br'[0-9]+\.[0-9A-Za-z.]+')
    _incomplete_version_number_re = re.compile(br'.*\.[A-Za-z]')

    def section_is_released_version(self, title):
        """Whether this section is for a released version.

        True if the given level-2 section title indicates that this section
        contains released changes, otherwise False.
        """
        # Assume that a released version has a numerical version number
        # that follows a particular pattern. These criteria may be revised
        # as needed in future versions of this script.
        version_number = re.search(self._version_number_re, title)
        if version_number:
            return not re.search(self._incomplete_version_number_re,
                                 version_number.group(0))
        else:
            return False

    def unreleased_version_title(self):
        """The title to use if creating a new section for an unreleased version."""
        # pylint: disable=no-self-use; this method may be overridden
        return b'Unreleased changes'

    def __init__(self, input_stream):
        """Create a changelog object.

        Populate the changelog object from the content of the file
        input_stream. This is typically a file opened for reading, but
        can be any generator returning the lines to read.
        """
        # Content before the level-2 section where the new entries are to be
        # added.
        self.header = []
        # Content of the level-3 sections of where the new entries are to
        # be added.
        self.section_content = OrderedDict()
        for section in STANDARD_SECTIONS:
            self.section_content[section] = []
        # Content of level-2 sections for already-released versions.
        self.trailer = []
        self.read_main_file(input_stream)

    def read_main_file(self, input_stream):
        """Populate the changelog object from the content of the file.

        This method is only intended to be called as part of the constructor
        of the class and may not act sensibly on an object that is already
        partially populated.
        """
        # Parse the first level-2 section, containing changelog entries
        # for unreleased changes.
        # If we'll be expanding this section, everything before the first
        # level-3 section title ("###...") following the first level-2
        # section title ("##...") is passed through as the header
        # and everything after the second level-2 section title is passed
        # through as the trailer. Inside the first level-2 section,
        # split out the level-3 sections.
        # If we'll be creating a new version, the header is everything
        # before the point where we want to add the level-2 section
        # for this version, and the trailer is what follows.
        level_2_seen = 0
        current_section = None
        for line in input_stream:
            level, content = self.title_level(line)
            if level == 2:
                level_2_seen += 1
                if level_2_seen == 1:
                    if self.section_is_released_version(content):
                        self.header.append(b'## ' +
                                           self.unreleased_version_title() +
                                           b'\n\n')
                        level_2_seen = 2
            elif level == 3 and level_2_seen == 1:
                current_section = content
                self.section_content.setdefault(content, [])
            if level_2_seen == 1 and current_section is not None:
                if level != 3 and line.strip():
                    self.section_content[current_section].append(line)
            elif level_2_seen <= 1:
                self.header.append(line)
            else:
                self.trailer.append(line)

    def add_file(self, input_stream):
        """Add changelog entries from a file.

        Read lines from input_stream, which is typically a file opened
        for reading. These lines must contain a series of level 3
        Markdown sections with recognized titles. The corresponding
        content is injected into the respective sections in the changelog.
        The section titles must be either one of the hard-coded values
        in STANDARD_SECTIONS in assemble_changelog.py or already present
        in ChangeLog.md. Section titles must match byte-for-byte except that
        leading or trailing whitespace is ignored.
        """
        filename = input_stream.name
        current_section = None
        for line_number, line in enumerate(input_stream, 1):
            if not line.strip():
                continue
            level, content = self.title_level(line)
            if level == 3:
                current_section = content
                if current_section not in self.section_content:
                    raise InputFormatError(filename, line_number,
                                           'Section {} is not recognized',
                                           str(current_section)[1:])
            elif level == 0:
                if current_section is None:
                    raise InputFormatError(filename, line_number,
                                           'Missing section title at the beginning of the file')
                self.section_content[current_section].append(line)
            else:
                raise InputFormatError(filename, line_number,
                                       'Only level 3 headers (###) are permitted')

    def write(self, filename):
        """Write the changelog to the specified file.
        """
        with open(filename, 'wb') as out:
            for line in self.header:
                out.write(line)
            for section, lines in self.section_content.items():
                if not lines:
                    continue
                out.write(b'### ' + section + b'\n\n')
                for line in lines:
                    out.write(line)
                out.write(b'\n')
            for line in self.trailer:
                out.write(line)


@functools.total_ordering
class FileMergeTimestamp:
    """A timestamp indicating when a file was merged.

    If file1 was merged before file2, then
    FileMergeTimestamp(file1) <= FileMergeTimestamp(file2).
    """

    # Categories of files. A lower number is considered older.
    MERGED = 0
    COMMITTED = 1
    LOCAL = 2

    @staticmethod
    def creation_hash(filename):
        """Return the git commit id at which the given file was created.

        Return None if the file was never checked into git.
        """
        hashes = subprocess.check_output(['git', 'log', '--format=%H', '--', filename])
        if not hashes:
            # The file was never checked in.
            return None
        hashes = hashes.rstrip(b'\n')
        last_hash = hashes[hashes.rfind(b'\n')+1:]
        return last_hash

    @staticmethod
    def list_merges(some_hash, target, *options):
        """List merge commits from some_hash to target.

        Pass options to git to select which commits are included.
        """
        text = subprocess.check_output(['git', 'rev-list',
                                        '--merges', *options,
                                        b'..'.join([some_hash, target])])
        return text.rstrip(b'\n').split(b'\n')

    @classmethod
    def merge_hash(cls, some_hash):
        """Return the git commit id at which the given commit was merged.

        Return None if the given commit was never merged.
        """
        target = b'HEAD'
        # List the merges from some_hash to the target in two ways.
        # The ancestry list is the ones that are both descendants of
        # some_hash and ancestors of the target.
        ancestry = frozenset(cls.list_merges(some_hash, target,
                                             '--ancestry-path'))
        # The first_parents list only contains merges that are directly
        # on the target branch. We want it in reverse order (oldest first).
        first_parents = cls.list_merges(some_hash, target,
                                        '--first-parent', '--reverse')
        # Look for the oldest merge commit that's both on the direct path
        # and directly on the target branch. That's the place where some_hash
        # was merged on the target branch. See
        # https://stackoverflow.com/questions/8475448/find-merge-commit-which-include-a-specific-commit
        for commit in first_parents:
            if commit in ancestry:
                return commit
        return None

    @staticmethod
    def commit_timestamp(commit_id):
         """Return the timestamp of the given commit."""
         text = subprocess.check_output(['git', 'show', '-s',
                                         '--format=%ct',
                                         commit_id])
         return datetime.datetime.utcfromtimestamp(int(text))

    @staticmethod
    def file_timestamp(filename):
        """Return the modification timestamp of the given file."""
        mtime = os.stat(filename).st_mtime
        return datetime.datetime.fromtimestamp(mtime)

    def __init__(self, filename):
        """Determine the timestamp at which the file was merged."""
        self.filename = filename
        creation_hash = self.creation_hash(filename)
        if not creation_hash:
            self.category = self.LOCAL
            self.datetime = self.file_timestamp(filename)
            return
        merge_hash = self.merge_hash(creation_hash)
        if not merge_hash:
            self.category = self.COMMITTED
            self.datetime = self.commit_timestamp(creation_hash)
            return
        self.category = self.MERGED
        self.datetime = self.commit_timestamp(merge_hash)

    def sort_key(self):
        """"Return a sort key for this merge timestamp object.

        ts1.sort_key() < ts2.sort_key() if and only if ts1 is
        considered to be older than ts2.
        """
        return (self.category, self.datetime, self.filename)

    def __eq__(self, other):
        return self.sort_key() == other.sort_key()

    def __lt__(self, other):
        return self.sort_key() < other.sort_key()


def check_output(generated_output_file, main_input_file, merged_files):
    """Make sanity checks on the generated output.

    The intent of these sanity checks is to have reasonable confidence
    that no content has been lost.

    The sanity check is that every line that is present in an input file
    is also present in an output file. This is not perfect but good enough
    for now.
    """
    generated_output = set(open(generated_output_file, 'rb'))
    for line in open(main_input_file, 'rb'):
        if line not in generated_output:
            raise LostContent('original file', line)
    for merged_file in merged_files:
        for line in open(merged_file, 'rb'):
            if line not in generated_output:
                raise LostContent(merged_file, line)

def finish_output(changelog, output_file, input_file, merged_files):
    """Write the changelog to the output file.

    The input file and the list of merged files are used only for sanity
    checks on the output.
    """
    if os.path.exists(output_file) and not os.path.isfile(output_file):
        # The output is a non-regular file (e.g. pipe). Write to it directly.
        output_temp = output_file
    else:
        # The output is a regular file. Write to a temporary file,
        # then move it into place atomically.
        output_temp = output_file + '.tmp'
    changelog.write(output_temp)
    check_output(output_temp, input_file, merged_files)
    if output_temp != output_file:
        os.rename(output_temp, output_file)

def remove_merged_entries(files_to_remove):
    for filename in files_to_remove:
        os.remove(filename)

def list_files_to_merge(options):
    """List the entry files to merge, oldest first.

    A file is considered older if it was merged earlier. See
    `FileMergeTimestamp` for details.
    """
    files_to_merge = glob.glob(os.path.join(options.dir, '*.md'))
    files_to_merge.sort(key=lambda f: FileMergeTimestamp(f).sort_key())
    return files_to_merge

def merge_entries(options):
    """Merge changelog entries into the changelog file.

    Read the changelog file from options.input.
    Read entries to merge from the directory options.dir.
    Write the new changelog to options.output.
    Remove the merged entries if options.keep_entries is false.
    """
    with open(options.input, 'rb') as input_file:
        changelog = ChangeLog(input_file)
    files_to_merge = list_files_to_merge(options)
    if not files_to_merge:
        sys.stderr.write('There are no pending changelog entries.\n')
        return
    for filename in files_to_merge:
        with open(filename, 'rb') as input_file:
            changelog.add_file(input_file)
    finish_output(changelog, options.output, options.input, files_to_merge)
    if not options.keep_entries:
        remove_merged_entries(files_to_merge)

def show_file_timestamps(options):
    """List the files to merge and their timestamp.

    This is only intended for debugging purposes.
    """
    files = list_files_to_merge(options)
    for filename in files:
        ts = FileMergeTimestamp(filename)
        print(ts.category, ts.datetime, filename)

def set_defaults(options):
    """Add default values for missing options."""
    output_file = getattr(options, 'output', None)
    if output_file is None:
        options.output = options.input
    if getattr(options, 'keep_entries', None) is None:
        options.keep_entries = (output_file is not None)

def main():
    """Command line entry point."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dir', '-d', metavar='DIR',
                        default='ChangeLog.d',
                        help='Directory to read entries from'
                             ' (default: ChangeLog.d)')
    parser.add_argument('--input', '-i', metavar='FILE',
                        default='ChangeLog.md',
                        help='Existing changelog file to read from and augment'
                             ' (default: ChangeLog.md)')
    parser.add_argument('--keep-entries',
                        action='store_true', dest='keep_entries', default=None,
                        help='Keep the files containing entries'
                             ' (default: remove them if --output/-o is not specified)')
    parser.add_argument('--no-keep-entries',
                        action='store_false', dest='keep_entries',
                        help='Remove the files containing entries after they are merged'
                             ' (default: remove them if --output/-o is not specified)')
    parser.add_argument('--output', '-o', metavar='FILE',
                        help='Output changelog file'
                             ' (default: overwrite the input)')
    parser.add_argument('--list-files-only',
                        action='store_true',
                        help='Only list the files that would be processed (with some debugging information)')
    options = parser.parse_args()
    set_defaults(options)
    if options.list_files_only:
        show_file_timestamps(options)
        return
    merge_entries(options)

if __name__ == '__main__':
    main()
