#!/usr/bin/env python3

# Copyright (C) Arm Limited, 2022 All rights reserved.

# This script (hereafter referred to as the Software) is provided on an as-is
# basis as an example of the type of static analysis that can be performed to
# check if user source code is vulnerable to CVE-2021-42574 or CVE-2021-42694.
# Arm makes no guarantees about the correctness or completeness of the Software.

# You accept that the Software has not been tested by Arm therefore the Software
# is provided "as is", without warranty of any kind, express or implied. In no
# event shall the authors or copyright holders be liable for any claim, damages
# or other liability, whether in action or contract, tort or otherwise, arising
# from, out of or in connection with the Software or the use of Software.

#pylint: disable=missing-module-docstring

import argparse
import json
import unicodedata
import os
import sys

#pylint: disable=missing-function-docstring
def init():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--input', required=True,
                        help='Input source file or directory.',
                        metavar='input.c')
    parser.add_argument('-r', '--recurse', required=False,
                        action='store_true', default=False,
                        help='Scan input directory recursively.')
    parser.add_argument('-um', '--unicode_mode', required=False,
                        action='store_true', default=False,
                        help='Detect all non-printable unicode characters, '
                             'instead of using an ordinal threshold for detection. '
                             'Note that this method cannot detect misleading printable '
                             'characters that look like other printable characters.')
    parser.add_argument('-ot', '--ordinal_threshold', required=False,
                        type=int, default=127,
                        help='Ordinal threshold to use to flag unicode characters. '
                             'Defaults to 127 to flag all non-ASCII characters.',
                        metavar='127')
    parser.add_argument('-ef', '--exclusions_file', required=False,
                        default=None, metavar='excluded_characters.txt',
                        help='An optional UTF-8-encoded text file that contains '
                             'characters that will be excluded from detection. '
                             'You can use this to remove false positives when '
                             'processing source code that might contain '
                             'non-English characters.')
    parser.add_argument('-o', '--output', required=False,
                        default=None, metavar='info.json',
                        help='JSON output file containing information about'
                             ' occurrences found.')
    return parser.parse_args()


def main():
    opts = init()

    flagged_chars_list = detect(opts.input,
                                opts.recurse,
                                opts.ordinal_threshold,
                                opts.unicode_mode,
                                opts.exclusions_file)

    if len(flagged_chars_list) > 0:
        as_string = json.dumps(
            flagged_chars_list,
            indent=4,
            sort_keys=True,
            ensure_ascii=False
        ).encode('utf-8').decode('utf-8')
        if opts.output is not None:
            with open(opts.output, 'w') as f:
                f.write(as_string)
        else:
            print(as_string)
    else:
        if opts.output is not None:
            with open(opts.output, 'w') as f:
                f.write('[]')

#pylint: disable=missing-function-docstring
def summarize_results(ordinal_threshold, unicode_mode, total_occurrences_found, total_chars_found):
    if total_chars_found > 0:
        if not unicode_mode:
            print('Found {:,} character{} with {:,} total occurrence{}, '
                  'using a maximum ordinal value theshold of '
                  '{:,}.'.format(total_chars_found,
                                 's' if total_chars_found > 1 else '',
                                 total_occurrences_found,
                                 's' if total_occurrences_found > 1 else '',
                                 ordinal_threshold))
        else:
            print('Found {:,} character{} with {:,} total occurrence{}.'.format(
                total_chars_found,
                's' if total_chars_found > 1 else '',
                total_occurrences_found,
                's' if total_occurrences_found > 1 else ''
            ))
    else:
        if not unicode_mode:
            print('No characters found using a maxmimum ordinal value threshold of {:,}.'.format(
                ordinal_threshold
            ))
        else:
            print('No non-printable Unicode characters found.')
    print()

#pylint: disable=too-many-locals
#pylint: disable=missing-function-docstring
def check_file(ordinal_threshold,
               unicode_mode,
               exclusions_list,
               source_string_lines,
               verbose=False):
    # Perform the detection
    flagged_chars = {}
    line_number = 1
    column_number = 1
    for source_string in source_string_lines:
        column_number = 1
        #pylint: disable=consider-using-enumerate
        for i in range(0, len(source_string)):
            char = source_string[i]
            ordinal = ord(char)
            unicode_category = unicodedata.category(char)
            is_printable = not unicode_category[0] == 'C'
            #pylint: disable=too-many-boolean-expressions
            if ((not unicode_mode and ordinal > ordinal_threshold) or \
                (unicode_mode and not is_printable)) and \
                ordinal not in exclusions_list and char not in ['\r', '\n']:
                if ordinal not in flagged_chars:
                    flagged_chars[ordinal] = {
                        'character': char if is_printable else 'U+{}'.format(ordinal),
                        'unicode_category': unicode_category,
                        'occurrences': 1,
                        'locations': [{
                            'line': line_number,
                            'column': column_number,
                            'line_text': source_string
                        }]
                    }
                else:
                    flagged_chars[ordinal]['occurrences'] += 1
                    flagged_chars[ordinal]['locations'].append({
                        'line': line_number,
                        'column': column_number,
                        'line_text': source_string
                    })
            column_number += 1
        line_number += 1
    flagged_chars_list = []
    occurrences_found = 0
    for key, value in flagged_chars.items():
        flagged_chars_list.append({
            'character': value['character'],
            'unicode_category': value['unicode_category'],
            'ordinal': key,
            'occurrences': value['occurrences'],
            'locations': value['locations']
        })
        occurrences_found += value['occurrences']
    if verbose:
        summarize_results(ordinal_threshold,
                          unicode_mode,
                          occurrences_found,
                          len(flagged_chars_list))
    return flagged_chars_list, occurrences_found

#pylint: disable=too-many-arguments
#pylint: disable=missing-function-docstring
def load_and_check_file(ordinal_threshold,
                        unicode_mode,
                        exclusions_list,
                        results, unique_flagged_chars,
                        total_occurrences_found,
                        input_file, verbose=False):
    source_string_lines = []
    checked = False
    if os.path.isfile(input_file):
        if verbose:
            print('Checking file {} ...'.format(input_file))
        try:
            with open(input_file, 'r', encoding='utf-8') as f:
                source_string_lines += f.readlines()
            flagged_chars_list, occurrences_found = check_file(ordinal_threshold,
                                                               unicode_mode,
                                                               exclusions_list,
                                                               source_string_lines)
            for entry in flagged_chars_list:
                unique_flagged_chars.add(entry['ordinal'])
            total_occurrences_found += occurrences_found
            if occurrences_found > 0:
                results.append({
                    'filepath': input_file,
                    'detected_characters': flagged_chars_list
                })
            checked = True
        except UnicodeDecodeError:
            if verbose:
                print('WARNING: Skipping file {} as it is does not have '
                      'valid UTF-8 encoding'.format(input_file))
    else:
        if verbose:
            print('WARNING: Skipping file {} as it no longer exists'.format(input_file))
    return total_occurrences_found, checked

#pylint: disable=too-many-locals
#pylint: disable=missing-function-docstring
def detect(input_path,
           scan_recurse=False,
           ordinal_threshold=127,
           unicode_mode=False,
           exclusions_file=None):

    # Validate inputs
    #pylint: disable=too-many-branches
    if ordinal_threshold < 0:
        print('ERROR: You cannot specify a negative ordinal threshold!')
        sys.exit(1)

    # Load exclusions file, if there is one
    exclusions_list = []
    if exclusions_file is not None:
        content = None
        with open(exclusions_file, 'r', encoding='utf-8') as f:
            content = f.readlines()
        content = ''.join([x.strip() for x in content])
        for char in content:
            exclusions_list.append(ord(char))

    # Load source files, and check them as you go
    results = []
    unique_flagged_chars = set()
    total_occurrences_found = 0
    total_files_checked = 0
    if os.path.isdir(input_path):
        # Load all recursively
        if scan_recurse:
            for path_root, path_dir, path_file in os.walk(input_path):
                # Filter out hidden directories on Linux and macOS
                path_dir[:] = [d for d in path_dir if not d.startswith('.')]
                for file in path_file:
                    input_file = os.path.join(path_root, file)
                    if file.startswith('.'):
                        print('Skipped hidden item {}\n'.format(input_file))
                        continue
                    total_occurrences_found, checked = load_and_check_file(ordinal_threshold,
                                                                           unicode_mode,
                                                                           exclusions_list,
                                                                           results,
                                                                           unique_flagged_chars,
                                                                           total_occurrences_found,
                                                                           input_file)
                    if checked:
                        total_files_checked += 1
        else:
            # Load all single directory
            for file in os.listdir(input_path):
                input_file = os.path.join(input_path, file)
                if file.startswith('.'):
                    print('Skipped hidden item {}\n'.format(input_file))
                    continue
                total_occurrences_found, checked = load_and_check_file(ordinal_threshold,
                                                                       unicode_mode,
                                                                       exclusions_list,
                                                                       results,
                                                                       unique_flagged_chars,
                                                                       total_occurrences_found,
                                                                       input_file)
                if checked:
                    total_files_checked += 1
    else:
        if scan_recurse:
            print('WARNING: You specified -r / --recurse to recursively scan a directory, '
                  'but specified an input file instead of an input directory.\n')
        # Load single file
        total_occurrences_found, checked = load_and_check_file(ordinal_threshold,
                                                               unicode_mode,
                                                               exclusions_list,
                                                               results,
                                                               unique_flagged_chars,
                                                               total_occurrences_found,
                                                               input_path)
        if checked:
            total_files_checked += 1

    # Save the outcome
    total_chars_found = len(unique_flagged_chars)
    if len(exclusions_list) > 0:
        print('Note: The following character{} excluded from detection:\n{}'.format(
            's are' if len(exclusions_list) > 1 else ' is',
            json.dumps([{
                'ordinal': x,
                'character': chr(x) if unicodedata.category(chr(x))[0] != 'C' else 'U+{}'.format(x),
                'unicode_category': unicodedata.category(chr(x))
            } for x in exclusions_list],
                       indent=4,
                       sort_keys=True,
                       ensure_ascii=False).encode('utf-8').decode('utf-8')
        ))

    final_summary_title_string = 'Overall results for {:,} file{}:'.format(
        total_files_checked,
        's' if total_files_checked > 0 else ''
    )
    print('\n{}\n{}'.format(
        final_summary_title_string,
        ''.join(['=' for i in range(0, len(final_summary_title_string))])
    ))
    summarize_results(ordinal_threshold, unicode_mode, total_occurrences_found, total_chars_found)

    # Return outcome
    return results


if __name__ == '__main__':
    main()
