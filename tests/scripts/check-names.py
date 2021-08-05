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
are consistent with the house style and are also self-consistent.
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

# Naming patterns to check against
MACRO_PATTERN = r"^MBEDTLS_[0-9A-Z_]*[0-9A-Z]$|^YOTTA_[0-9A-Z_]*[0-9A-Z]$"
IDENTIFIER_PATTERN = r"^(mbedtls|psa)_[0-9a-z_]*[0-9a-z]$"

class Match(object):
    def __init__(self, filename, line, pos, name):
        self.filename = filename
        self.line = line
        self.pos = pos
        self.name = name
    
    def __str__(self):
        return self.name

class Problem(object):
    def __init__(self):
        self.textwrapper = textwrap.TextWrapper()
        self.textwrapper.initial_indent = "  * "
        self.textwrapper.subsequent_indent = "    "

class SymbolNotInHeader(Problem):
    def __init__(self, symbol_name):
        self.symbol_name = symbol_name
        Problem.__init__(self)

    def __str__(self):
        return self.textwrapper.fill(
            "'{0}' was found as an available symbol in the output of nm, "
            "however it was not declared in any header files."
            .format(self.symbol_name))

class PatternMismatch(Problem):
    def __init__(self, pattern, match):
        self.pattern = pattern
        self.match = match
        Problem.__init__(self)
    
    def __str__(self):
        return self.textwrapper.fill(
            "{0}: '{1}' does not match the required pattern '{2}'."
            .format(self.match.filename, self.match.name, self.pattern))

class Typo(Problem):
    def __init__(self, match):
        self.match = match
        Problem.__init__(self)
    
    def __str__(self):
        return self.textwrapper.fill(
            "{0}: '{1}' looks like a typo. It was not found in any macros or "
            "any enums. If this is not a typo, put //no-check-names after it."
            .format(self.match.filename, self.match.name))

class NameCheck(object):
    def __init__(self):
        self.log = None
        self.check_repo_path()
        self.return_code = 0
        self.excluded_files = ["compat-1.3.h"]
        self.typo_check_pattern = r"XXX|__|_$|^MBEDTLS_.*CONFIG_FILE$"

    def set_return_code(self, return_code):
        if return_code > self.return_code:
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
        current_dir = os.path.realpath('.')
        root_dir = os.path.dirname(os.path.dirname(
            os.path.dirname(os.path.realpath(__file__))))
        if current_dir != root_dir:
            raise Exception("Must be run from Mbed TLS root")

    def get_files(self, directory):
        filenames = []
        for root, dirs, files in sorted(os.walk(directory)):
            for filename in sorted(files):
                if (filename not in self.excluded_files and
                        filename.endswith((".c", ".h"))):
                    filenames.append(os.path.join(root, filename))
        return filenames

    def parse_macros(self, header_files):
        """
        Parse all macros defined by #define preprocessor directives.

        Args:
            header_files: A list of filepaths to look through.
        
        Returns:
            A list of Match objects for the macros.
        """
        MACRO_REGEX = r"#define (?P<macro>\w+)"
        NON_MACROS = (
            "asm", "inline", "EMIT", "_CRT_SECURE_NO_DEPRECATE", "MULADDC_"
        )

        macros = []

        for header_file in header_files:
            with open(header_file, "r") as header:
                for line in header:
                    macro = re.search(MACRO_REGEX, line)
                    if (macro and
                        not macro.group("macro").startswith(NON_MACROS)):
                        macros.append(Match(
                            header_file,
                            line,
                            (macro.start(), macro.end()),
                            macro.group("macro")))

        return macros

    def parse_MBED_names(self, header_files, library_files):
        """
        Parse all words in the file that begin with MBED. Includes macros.

        Args:
            header_files: A list of filepaths to look through.
            library_files: A list of filepaths to look through.
        
        Returns:
            A list of Match objects for words beginning with MBED.
        """
        MBED_names = []
        
        for filename in header_files + library_files:
            with open(filename, "r") as fp:
                for line in fp:
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
            header_files: A list of filepaths to look through.

        Returns:
            A list of (enum constants, containing filename).
        """

        enum_consts = []

        for header_file in header_files:
            # Emulate a finite state machine to parse enum declarations.
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
                    elif state is 1:
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
        based on some huersitics. Assumes every line that is not a comment or a
        preprocessor directive contains some identifier.

        Args:
            header_files: A list of filepaths to look through.
        
        Returns:
            A list of (identifier, containing filename)
        """
        EXCLUDED_DECLARATIONS = (
            r"^(extern \"C\"|(typedef )?(struct|enum)( {)?$|};?$|$)"
        )

        identifiers = []

        for header_file in header_files:
            with open(header_file, "r") as header:
                in_block_comment = False

                for line in header:
                    # Skip parsing this line if it begins or ends a block
                    # comment, and set the state machine's state.
                    if re.search(r"/\*", line):
                        in_block_comment = True
                        continue
                    elif re.search(r"\*/", line) and in_block_comment:
                        in_block_comment = False
                        continue
                    
                    # Skip parsing this line if it's a line comment, or if it
                    # begins with a preprocessor directive
                    if in_block_comment or re.match(r"(//|#)", line):
                        continue

                    if re.match(EXCLUDED_DECLARATIONS, line):
                        continue
                
                    identifier = re.search(
                        # Matches: "mbedtls_aes_init("
                        r"([a-zA-Z_][a-zA-Z0-9_]*)\(|"
                        # Matches: "(*f_rng)("
                        r"\(\*(.+)\)\(|"
                        # TODO: unknown purpose
                        r"(\w+)\W*$",
                        line
                    )

                    if identifier:
                        for group in identifier.groups():
                            if group:
                                identifiers.append(Match(
                                    header_file,
                                    line,
                                    (identifier.start(), identifier.end()),
                                    identifier.group(0)))

        return identifiers

    def parse_symbols(self):
        """
        Compile the Mbed TLS libraries, and parse the TLS, Crypto, and x509
        object files using nm to retrieve the list of referenced symbols.
        
        Returns:
            A list of unique symbols defined and used in the libraries.
        """

        symbols = []

        # Back up the config and atomically compile with the full configratuion.
        shutil.copy("include/mbedtls/mbedtls_config.h",
                    "include/mbedtls/mbedtls_config.h.bak")        
        try:
            subprocess.run(
                ["perl", "scripts/config.pl", "full"],
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
            self.log.error(error)
            self.set_return_code(2)
        finally:
            shutil.move("include/mbedtls/mbedtls_config.h.bak",
                        "include/mbedtls/mbedtls_config.h")

        return symbols

    def parse_symbols_from_nm(self, object_files):
        """
        Run nm to retrieve the list of referenced symbols in each object file.
        Does not return the position data since it is of no use.

        Returns:
            A list of unique symbols defined and used in any of the object files.
        """
        UNDEFINED_SYMBOL = r"^\S+: +U |^$|^\S+:$"
        VALID_SYMBOL = r"^\S+( [0-9A-Fa-f]+)* . _*(?P<symbol>\w+)"

        symbols = []

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
                if symbol:
                    symbols.append(symbol.group('symbol'))
                else:
                    self.log.error(line)
        
        return symbols

    def parse_names_in_source(self):
        """
        Calls each parsing function to retrieve various elements of the code,
        together with their source location. Puts the parsed values in the
        internal variable self.parse_result.
        """
        self.log.info("Parsing source code...")

        m_headers = self.get_files(os.path.join("include", "mbedtls"))
        p_headers = self.get_files(os.path.join("include", "psa"))
        libraries = self.get_files("library")
        
        all_macros = self.parse_macros(m_headers + ["configs/config-default.h"])
        enum_consts = self.parse_enum_consts(m_headers)
        identifiers = self.parse_identifiers(m_headers + p_headers)
        symbols = self.parse_symbols()
        mbed_names = self.parse_MBED_names(m_headers, libraries)
        
        # Remove identifier macros like mbedtls_printf or mbedtls_calloc
        macros = list(set(all_macros) - set(identifiers))

        self.log.info("Found:")
        self.log.info("  {} Macros".format(len(all_macros)))
        self.log.info("  {} Enum Constants".format(len(enum_consts)))
        self.log.info("  {} Identifiers".format(len(identifiers)))
        self.log.info("  {} Exported Symbols".format(len(symbols)))
        self.log.info("Analysing...")

        self.parse_result = {
            "macros": macros,
            "enum_consts": enum_consts,
            "identifiers": identifiers,
            "symbols": symbols,
            "mbed_names": mbed_names
        }

    def perform_checks(self):
        """
        Perform each check in order, output its PASS/FAIL status. Maintain an
        overall test status, and output that at the end.
        """
        problems = 0

        problems += self.check_symbols_declared_in_header()

        pattern_checks = [
            ("macros", MACRO_PATTERN),
            ("enum_consts", MACRO_PATTERN),
            ("identifiers", IDENTIFIER_PATTERN)]
        for group, check_pattern in pattern_checks:
            problems += self.check_match_pattern(group, check_pattern)

        problems += self.check_for_typos()

        self.log.info("=============")
        if problems > 0:
            self.log.info("FAIL: {0} problem(s) to fix".format(str(problems)))
        else:
            self.log.info("PASS")

    def check_symbols_declared_in_header(self):
        """
        Perform a check that all detected symbols in the library object files
        are properly declared in headers.
        
        Outputs to the logger the PASS/FAIL status, followed by the location of
        problems.

        Returns the number of problems that needs fixing.
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

        if problems:
            self.set_return_code(1)
            self.log.info("All symbols in header: FAIL")
            for problem in problems:
                self.log.info(str(problem) + "\n")
        else:
            self.log.info("All symbols in header: PASS")
        
        return len(problems)

    def check_match_pattern(self, group_to_check, check_pattern):
        problems = []
        for item_match in self.parse_result[group_to_check]:
            if not re.match(check_pattern, item_match.name):
                problems.append(PatternMismatch(check_pattern, item_match))
        
        if problems:
            self.set_return_code(1)
            self.log.info("Naming patterns of {}: FAIL".format(group_to_check))
            for problem in problems:
                self.log.info(str(problem) + "\n")
        else:
            self.log.info("Naming patterns of {}: PASS".format(group_to_check))
        
        return len(problems)

    def check_for_typos(self):
        problems = []
        all_caps_names = list(set([
            match.name for match
            in self.parse_result["macros"] + self.parse_result["enum_consts"]]
        ))

        TYPO_EXCLUSION = r"XXX|__|_$|^MBEDTLS_.*CONFIG_FILE$"

        for name_match in self.parse_result["mbed_names"]:
            if name_match.name not in all_caps_names:
                if not re.search(TYPO_EXCLUSION, name_match.name):
                    problems.append(Typo(name_match))

        if problems:
            self.set_return_code(1)
            self.log.info("Likely typos: FAIL")
            for problem in problems:
                self.log.info(str(problem) + "\n")
        else:
            self.log.info("Likely typos: PASS")
        
        return len(problems)

def main():
    """
    Main function, parses command-line arguments.
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
                        help="enable script debug outputs")
    
    args = parser.parse_args()

    try:
        name_check = NameCheck()
        name_check.setup_logger(verbose=args.verbose)
        name_check.parse_names_in_source()
        name_check.perform_checks()
        sys.exit(name_check.return_code)
    except Exception:
        traceback.print_exc()
        sys.exit(2)


if __name__ == "__main__":
    main()
