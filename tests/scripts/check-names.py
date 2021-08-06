#!/usr/bin/env python3
#
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

"""
This script confirms that the naming of all symbols and identifiers in Mbed TLS
are consistent with the house style and are also self-consistent. It performs
the following checks:

- All exported and available symbols in the library object files, are explicitly
  declared in the header files.
- All macros, constants, and identifiers (function names, struct names, etc)
  follow the required pattern.
- Typo checking: All words that begin with MBED exist as macros or constants.
"""

import argparse
import textwrap
import os
import sys
import traceback
import re
import shutil
import subprocess
import logging

# Naming patterns to check against. These are defined outside the NameCheck
# class for ease of modification.
MACRO_PATTERN = r"^(MBEDTLS|PSA)_[0-9A-Z_]*[0-9A-Z]$"
CONSTANTS_PATTERN = MACRO_PATTERN
IDENTIFIER_PATTERN = r"^(mbedtls|psa)_[0-9a-z_]*[0-9a-z]$"

class Match(object):
    """
    A class representing a match, together with its found position.

    Fields:
    * filename: the file that the match was in.
    * line: the full line containing the match.
    * pos: a tuple of (start, end) positions on the line where the match is.
    * name: the match itself.
    """
    def __init__(self, filename, line, pos, name):
        self.filename = filename
        self.line = line
        self.pos = pos
        self.name = name

class Problem(object):
    """
    A parent class representing a form of static analysis error.

    Fields:
    * textwrapper: a TextWrapper instance to format problems nicely.
    """
    def __init__(self):
        self.textwrapper = textwrap.TextWrapper()
        self.textwrapper.width = 80
        self.textwrapper.initial_indent = "    * "
        self.textwrapper.subsequent_indent = "      "

class SymbolNotInHeader(Problem):
    """
    A problem that occurs when an exported/available symbol in the object file
    is not explicitly declared in header files. Created with
    NameCheck.check_symbols_declared_in_header()

    Fields:
    * symbol_name: the name of the symbol.
    """
    def __init__(self, symbol_name):
        self.symbol_name = symbol_name
        Problem.__init__(self)

    def __str__(self):
        return self.textwrapper.fill(
            "'{0}' was found as an available symbol in the output of nm, "
            "however it was not declared in any header files."
            .format(self.symbol_name))

class PatternMismatch(Problem):
    """
    A problem that occurs when something doesn't match the expected pattern.
    Created with NameCheck.check_match_pattern()

    Fields:
    * pattern: the expected regex pattern
    * match: the Match object in question
    """
    def __init__(self, pattern, match):
        self.pattern = pattern
        self.match = match
        Problem.__init__(self)

    def __str__(self):
        return self.textwrapper.fill(
            "{0}: '{1}' does not match the required pattern '{2}'."
            .format(self.match.filename, self.match.name, self.pattern))

class Typo(Problem):
    """
    A problem that occurs when a word using MBED doesn't appear to be defined as
    constants nor enum values. Created with NameCheck.check_for_typos()

    Fields:
    * match: the Match object of the MBED name in question.
    """
    def __init__(self, match):
        self.match = match
        Problem.__init__(self)

    def __str__(self):
        return self.textwrapper.fill(
            "{0}: '{1}' looks like a typo. It was not found in any macros or "
            "any enums. If this is not a typo, put //no-check-names after it."
            .format(self.match.filename, self.match.name))

class NameCheck(object):
    """
    Representation of the core name checking operation performed by this script.
    Shares a common logger, common excluded filenames, and a shared return_code.
    """
    def __init__(self):
        self.log = None
        self.check_repo_path()
        self.return_code = 0
        self.excluded_files = ["bn_mul", "compat-2.x.h"]

    def set_return_code(self, return_code):
        if return_code > self.return_code:
            self.log.debug("Setting new return code to {}".format(return_code))
            self.return_code = return_code

    def setup_logger(self, verbose=False):
        """
        Set up a logger and set the change the default logging level from
        WARNING to INFO. Loggers are better than print statements since their
        verbosity can be controlled.
        """
        self.log = logging.getLogger()
        if verbose:
            self.log.setLevel(logging.DEBUG)
        else:
            self.log.setLevel(logging.INFO)
        self.log.addHandler(logging.StreamHandler())

    def check_repo_path(self):
        """
        Check that the current working directory is the project root, and throw
        an exception if not.
        """
        if (not os.path.isdir("include") or
            not os.path.isdir("tests") or
            not os.path.isdir("library")):
            raise Exception("This script must be run from Mbed TLS root")

    def get_files(self, extension, directory):
        """
        Get all files that end with .extension in the specified directory
        recursively.

        Args:
        * extension: the file extension to search for, without the dot
        * directory: the directory to recursively search for

        Returns a List of relative filepaths.
        """
        filenames = []
        for root, dirs, files in sorted(os.walk(directory)):
            for filename in sorted(files):
                if (filename not in self.excluded_files and
                        filename.endswith("." + extension)):
                    filenames.append(os.path.join(root, filename))
        return filenames

    def parse_names_in_source(self):
        """
        Calls each parsing function to retrieve various elements of the code,
        together with their source location. Puts the parsed values in the
        internal variable self.parse_result.
        """
        self.log.info("Parsing source code...")
        self.log.debug(
            "The following files are excluded from the search: {}"
            .format(str(self.excluded_files))
        )

        m_headers = self.get_files("h", os.path.join("include", "mbedtls"))
        p_headers = self.get_files("h", os.path.join("include", "psa"))
        t_headers = ["3rdparty/everest/include/everest/everest.h",
                     "3rdparty/everest/include/everest/x25519.h"]
        d_headers = self.get_files("h", os.path.join("tests", "include", "test", "drivers"))
        l_headers = self.get_files("h", "library")
        libraries = self.get_files("c", "library") + [
            "3rdparty/everest/library/everest.c",
            "3rdparty/everest/library/x25519.c"]

        all_macros = self.parse_macros(
            m_headers + p_headers + t_headers + l_headers + d_headers)
        enum_consts = self.parse_enum_consts(
            m_headers + l_headers + t_headers)
        identifiers = self.parse_identifiers(
            m_headers + p_headers + t_headers + l_headers)
        mbed_names = self.parse_MBED_names(
            m_headers + p_headers + t_headers + l_headers + libraries)
        symbols = self.parse_symbols()

        # Remove identifier macros like mbedtls_printf or mbedtls_calloc
        identifiers_justname = [x.name for x in identifiers]
        actual_macros = []
        for macro in all_macros:
            if macro.name not in identifiers_justname:
                actual_macros.append(macro)

        self.log.debug("Found:")
        self.log.debug("  {} Macros".format(len(all_macros)))
        self.log.debug("  {} Non-identifier Macros".format(len(actual_macros)))
        self.log.debug("  {} Enum Constants".format(len(enum_consts)))
        self.log.debug("  {} Identifiers".format(len(identifiers)))
        self.log.debug("  {} Exported Symbols".format(len(symbols)))
        self.log.info("Analysing...")

        self.parse_result = {
            "macros": actual_macros,
            "enum_consts": enum_consts,
            "identifiers": identifiers,
            "symbols": symbols,
            "mbed_names": mbed_names
        }

    def parse_macros(self, header_files):
        """
        Parse all macros defined by #define preprocessor directives.

        Args:
        * header_files: A List of filepaths to look through.

        Returns a List of Match objects for the found macros.
        """
        MACRO_REGEX = r"# *define +(?P<macro>\w+)"
        NON_MACROS = (
            "asm", "inline", "EMIT", "_CRT_SECURE_NO_DEPRECATE", "MULADDC_"
        )

        macros = []
        self.log.debug("Looking for macros in {} files".format(len(header_files)))
        for header_file in header_files:
            with open(header_file, "r") as header:
                for line in header:
                    for macro in re.finditer(MACRO_REGEX, line):
                        if not macro.group("macro").startswith(NON_MACROS):
                            macros.append(Match(
                                header_file,
                                line,
                                (macro.start(), macro.end()),
                                macro.group("macro")))

        return macros

    def parse_MBED_names(self, files):
        """
        Parse all words in the file that begin with MBED. Includes macros.
        There have been typos of TLS, hence the broader check than MBEDTLS.

        Args:
        * files: a List of filepaths to look through.

        Returns a List of Match objects for words beginning with MBED.
        """
        MBED_names = []
        self.log.debug("Looking for MBED names in {} files".format(len(files)))
        for filename in files:
            with open(filename, "r") as fp:
                for line in fp:
                    # Ignore any names that are deliberately opted-out or in
                    # legacy error directives
                    if re.search(r"// *no-check-names|#error", line):
                        continue

                    for name in re.finditer(r"\bMBED.+?_[A-Z0-9_]*", line):
                        MBED_names.append(Match(
                            filename,
                            line,
                            (name.start(), name.end()),
                            name.group(0)
                            ))

        return MBED_names

    def parse_enum_consts(self, header_files):
        """
        Parse all enum value constants that are declared.

        Args:
        * header_files: A List of filepaths to look through.

        Returns a List of Match objects for the findings.
        """

        enum_consts = []
        self.log.debug("Looking for enum consts in {} files".format(len(header_files)))
        for header_file in header_files:
            # Emulate a finite state machine to parse enum declarations.
            # 0 = not in enum
            # 1 = inside enum
            # 2 = almost inside enum
            state = 0
            with open(header_file, "r") as header:
                for line in header:
                    if state is 0 and re.match(r"^(typedef )?enum {", line):
                        state = 1
                    elif state is 0 and re.match(r"^(typedef )?enum", line):
                        state = 2
                    elif state is 2 and re.match(r"^{", line):
                        state = 1
                    elif state is 1 and re.match(r"^}", line):
                        state = 0
                    elif state is 1 and not re.match(r"^#", line):
                        enum_const = re.match(r"^\s*(?P<enum_const>\w+)", line)
                        if enum_const:
                            enum_consts.append(Match(
                                header_file,
                                line,
                                (enum_const.start(), enum_const.end()),
                                enum_const.group("enum_const")))

        return enum_consts

    def parse_identifiers(self, header_files):
        """
        Parse all lines of a header where a function identifier is declared,
        based on some huersitics. Highly dependent on formatting style.

        Args:
        * header_files: A List of filepaths to look through.

        Returns a List of Match objects with identifiers.
        """
        EXCLUDED_LINES = (
            r"^("
               r"extern \"C\"|"
               r"(typedef )?(struct|union|enum)( {)?$|"
               r"};?$|"
               r"$|"
               r"//|"
               r"#"
            r")"
        )

        identifiers = []
        self.log.debug("Looking for identifiers in {} files".format(len(header_files)))
        for header_file in header_files:
            with open(header_file, "r") as header:
                in_block_comment = False
                previous_line = None

                for line in header:
                    # Skip parsing this line if a block comment ends on it,
                    # but don't skip if it has just started -- there is a chance
                    # it ends on the same line.
                    if re.search(r"/\*", line):
                        in_block_comment = not in_block_comment
                    if re.search(r"\*/", line):
                        in_block_comment = not in_block_comment
                        continue

                    if in_block_comment:
                        previous_line = None
                        continue

                    if re.match(EXCLUDED_LINES, line):
                        previous_line = None
                        continue

                    # Match "^something something$", with optional inline/static
                    # This *might* be a function with its argument brackets on
                    # the next line, or a struct declaration, so keep note of it
                    if re.match(
                        r"(inline |static |typedef )*\w+ \w+$",
                        line):
                        previous_line = line
                        continue

                    # If previous line seemed to start an unfinished declaration
                    # (as above), and this line begins with a bracket, concat
                    # them and treat them as one line.
                    if previous_line and re.match(" *[\({]", line):
                        line = previous_line.strip() + line.strip()
                        previous_line = None

                    # Skip parsing if line has a space in front = hueristic to
                    # skip function argument lines (highly subject to formatting
                    # changes)
                    if line[0] == " ":
                        continue

                    identifier = re.search(
                        # Match something(
                        r".* \**(\w+)\(|"
                        # Match (*something)(
                        r".*\( *\* *(\w+) *\) *\(|"
                        # Match names of named data structures
                        r"(?:typedef +)?(?:struct|union|enum) +(\w+)(?: *{)?$|"
                        # Match names of typedef instances, after closing bracket
                        r"}? *(\w+)[;[].*",
                        line
                    )

                    if identifier:
                        # Find the group that matched, and append it
                        for group in identifier.groups():
                            if group:
                                identifiers.append(Match(
                                    header_file,
                                    line,
                                    (identifier.start(), identifier.end()),
                                    group))

        return identifiers

    def parse_symbols(self):
        """
        Compile the Mbed TLS libraries, and parse the TLS, Crypto, and x509
        object files using nm to retrieve the list of referenced symbols.
        Exceptions thrown here are rethrown because they would be critical
        errors that void several tests, and thus needs to halt the program. This
        is explicitly done for clarity.

        Returns a List of unique symbols defined and used in the libraries.
        """
        self.log.info("Compiling...")
        symbols = []

        # Back up the config and atomically compile with the full configratuion.
        shutil.copy("include/mbedtls/mbedtls_config.h",
                    "include/mbedtls/mbedtls_config.h.bak")
        try:
            # Use check=True in all subprocess calls so that failures are raised
            # as exceptions and logged.
            subprocess.run(
                ["python3", "scripts/config.py", "full"],
                encoding=sys.stdout.encoding,
                check=True
            )
            my_environment = os.environ.copy()
            my_environment["CFLAGS"] = "-fno-asynchronous-unwind-tables"
            subprocess.run(
                ["make", "clean", "lib"],
                env=my_environment,
                encoding=sys.stdout.encoding,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=True
            )

            # Perform object file analysis using nm
            symbols = self.parse_symbols_from_nm(
                ["library/libmbedcrypto.a",
                "library/libmbedtls.a",
                "library/libmbedx509.a"])

            symbols.sort()

            subprocess.run(
                ["make", "clean"],
                encoding=sys.stdout.encoding,
                check=True
            )
        except subprocess.CalledProcessError as error:
            self.set_return_code(2)
            raise error
        finally:
            shutil.move("include/mbedtls/mbedtls_config.h.bak",
                        "include/mbedtls/mbedtls_config.h")

        return symbols

    def parse_symbols_from_nm(self, object_files):
        """
        Run nm to retrieve the list of referenced symbols in each object file.
        Does not return the position data since it is of no use.

        Args:
        * object_files: a List of compiled object files to search through.

        Returns a List of unique symbols defined and used in any of the object
        files.
        """
        UNDEFINED_SYMBOL = r"^\S+: +U |^$|^\S+:$"
        VALID_SYMBOL = r"^\S+( [0-9A-Fa-f]+)* . _*(?P<symbol>\w+)"
        EXCLUSIONS = ("FStar", "Hacl")

        symbols = []

        # Gather all outputs of nm
        nm_output = ""
        for lib in object_files:
            nm_output += subprocess.run(
                ["nm", "-og", lib],
                encoding=sys.stdout.encoding,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=True
            ).stdout

        for line in nm_output.splitlines():
            if not re.match(UNDEFINED_SYMBOL, line):
                symbol = re.match(VALID_SYMBOL, line)
                if symbol and not symbol.group("symbol").startswith(EXCLUSIONS):
                    symbols.append(symbol.group("symbol"))
                else:
                    self.log.error(line)

        return symbols

    def perform_checks(self, show_problems: True):
        """
        Perform each check in order, output its PASS/FAIL status. Maintain an
        overall test status, and output that at the end.

        Args:
        * show_problems: whether to show the problematic examples.
        """
        self.log.info("=============")
        problems = 0

        problems += self.check_symbols_declared_in_header(show_problems)

        pattern_checks = [
            ("macros", MACRO_PATTERN),
            ("enum_consts", CONSTANTS_PATTERN),
            ("identifiers", IDENTIFIER_PATTERN)]
        for group, check_pattern in pattern_checks:
            problems += self.check_match_pattern(
                show_problems, group, check_pattern)

        problems += self.check_for_typos(show_problems)

        self.log.info("=============")
        if problems > 0:
            self.log.info("FAIL: {0} problem(s) to fix".format(str(problems)))
            if not show_problems:
                self.log.info("Remove --quiet to show the problems.")
        else:
            self.log.info("PASS")

    def check_symbols_declared_in_header(self, show_problems):
        """
        Perform a check that all detected symbols in the library object files
        are properly declared in headers.

        Args:
        * show_problems: whether to show the problematic examples.

        Returns the number of problems that need fixing.
        """
        problems = []
        for symbol in self.parse_result["symbols"]:
            found_symbol_declared = False
            for identifier_match in self.parse_result["identifiers"]:
                if symbol == identifier_match.name:
                    found_symbol_declared = True
                    break

            if not found_symbol_declared:
                problems.append(SymbolNotInHeader(symbol))

        self.output_check_result("All symbols in header", problems, show_problems)
        return len(problems)


    def check_match_pattern(self, show_problems, group_to_check, check_pattern):
        """
        Perform a check that all items of a group conform to a regex pattern.

        Args:
        * show_problems: whether to show the problematic examples.
        * group_to_check: string key to index into self.parse_result.
        * check_pattern: the regex to check against.

        Returns the number of problems that need fixing.
        """
        problems = []
        for item_match in self.parse_result[group_to_check]:
            if not re.match(check_pattern, item_match.name):
                problems.append(PatternMismatch(check_pattern, item_match))
            # Double underscore is a reserved identifier, never to be used
            if re.match(r".*__.*", item_match.name):
                problems.append(PatternMismatch("double underscore", item_match))

        self.output_check_result(
            "Naming patterns of {}".format(group_to_check),
            problems,
            show_problems)
        return len(problems)

    def check_for_typos(self, show_problems):
        """
        Perform a check that all words in the soure code beginning with MBED are
        either defined as macros, or as enum constants.

        Args:
        * show_problems: whether to show the problematic examples.

        Returns the number of problems that need fixing.
        """
        problems = []
        all_caps_names = list(set([
            match.name for match
            in self.parse_result["macros"] + self.parse_result["enum_consts"]]
        ))

        TYPO_EXCLUSION = r"XXX|__|_$|^MBEDTLS_.*CONFIG_FILE$"

        for name_match in self.parse_result["mbed_names"]:
            found = name_match.name in all_caps_names

            # Since MBEDTLS_PSA_ACCEL_XXX defines are defined by the
            # PSA driver, they will not exist as macros. However, they
            # should still be checked for typos using the equivalent
            # BUILTINs that exist.
            if "MBEDTLS_PSA_ACCEL_" in name_match.name:
                found = name_match.name.replace(
                    "MBEDTLS_PSA_ACCEL_",
                    "MBEDTLS_PSA_BUILTIN_") in all_caps_names

            if not found and not re.search(TYPO_EXCLUSION, name_match.name):
                problems.append(Typo(name_match))

        self.output_check_result("Likely typos", problems, show_problems)
        return len(problems)

    def output_check_result(self, name, problems, show_problems):
        """
        Write out the PASS/FAIL status of a performed check depending on whether
        there were problems.

        Args:
        * show_problems: whether to show the problematic examples.
        """
        if problems:
            self.set_return_code(1)
            self.log.info("{}: FAIL".format(name))
            if show_problems:
                self.log.info("")
                for problem in problems:
                    self.log.warn(str(problem) + "\n")
        else:
            self.log.info("{}: PASS".format(name))

def main():
    """
    Perform argument parsing, and create an instance of NameCheck to begin the
    core operation.
    """

    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "This script confirms that the naming of all symbols and identifiers "
            "in Mbed TLS are consistent with the house style and are also "
            "self-consistent.\n\n"
            "Expected to be run from the MbedTLS root directory."))

    parser.add_argument("-v", "--verbose",
                        action="store_true",
                        help="show parse results")

    parser.add_argument("-q", "--quiet",
                        action="store_true",
                        help="hide unnecessary text and problematic examples")

    args = parser.parse_args()

    try:
        name_check = NameCheck()
        name_check.setup_logger(verbose=args.verbose)
        name_check.parse_names_in_source()
        name_check.perform_checks(show_problems=not args.quiet)
        sys.exit(name_check.return_code)
    except subprocess.CalledProcessError as error:
        traceback.print_exc()
        print("!! Compilation faced a critical error, "
              "check-names can't continue further.")
        sys.exit(name_check.return_code)
    except Exception:
        traceback.print_exc()
        sys.exit(2)

if __name__ == "__main__":
    main()
