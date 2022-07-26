#!/usr/bin/env python3
"""
This script updates tests/src/certs.c using data from data_files.

You must run this script from an Mbed TLS root.

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

import sys
import os
import re
import tempfile

class FormatException(Exception):
    """ Exception that is raised when file has wrong format
    """
    typ = ""
    line = 0

    def __init__(self, typ, line, *args):
        super().__init__(args)
        self.typ = typ
        self.line = line

    def __str__(self):
        if self.typ == "eof":
            return "Reached end of file unexpectedly"
        elif self.typ == "beginline":
            return f"Begin File has wrong number of parameters on line {self.line}"
        elif self.typ == "beginbegin":
            return f"Encountered another Begin File line before End File on line {self.line}"
        elif self.typ == "nofile":
            return f"Can't open file specified in line {self.line}"
        return "Not known format exception"

class TypeEncodingException(Exception):
    def __init__(self, tried, line, *args):
        super().__init__(args)
        self.tried = tried
        self.line = line

    def __str__(self):
        return f"""The {self.tried} is not valid type/encoding on line {self.line}.
                Possible types are macro or variable\n
                Possible encoding is string and binary"""

class CertUpdater:
    """ Updater for certs.c"""
    col = 77

    def __init__(self):
        """Instantiate the updater for certs.c

        certs: path to certs.c
        """
        self.certs = "tests/src/certs.c"

    @staticmethod
    def byte_to_array(filename):
        """ Reads file and returns as hex array
        """
        final = ""
        with open(filename, "rb") as f:
            data = f.read()
            data = data.hex()
            add = ["0x"+data[i:i+2] for i in range(0, len(data), 2)]
            i = 0
            column = 12
            while i + column < len(add):
                final += "    " + ", ".join(add[i:i+column]) + ",\n"
                i += column
            final += "    " + ", ".join(add[i:]) + "\n"
        return final

    def type_var_bin(self, name, filename):
        """ Generates code snipper to be added
        name: name of variable
        filename: where value of variable stored
        """
        output = "const unsigned char " + name + "[] = {\n"
        output += self.byte_to_array(filename)
        output += "};\n"
        return output

    @staticmethod
    def type_var_string(name, filename):
        """ Generates code snipper to be added
        name: name of variable
        filename: where value of variable stored
        """
        output = "const char " + name + "[] =\n"
        with open(filename) as f:
            for line in f.read().splitlines():
                output += "    \"" + line + "\\r\\n\"\n"
            output = output[:-1] + ";\n"
        return output

    def type_macro_bin(self, name, filename):
        """ Generates code snipper to be added
        name: name of macro
        filename: where value of macro stored
        """
        output = "#define " + name + " {\n"
        output += self.byte_to_array(filename)
        output = "".join([(line + (self.col-len(line))*" " + "\\\n")
                          for line in output.splitlines()])
        output += "}\n"
        return output

    def type_macro_string(self, name, filename):
        """ Generates code snipper to be added
        name: name of macro
        filename: where value of macro stored
        """
        output = "#define " + name + "\n"
        with open(filename) as f:
            for line in f.read().splitlines()[:-1]:
                output += "    \"" + line + "\\r\\n\"\n"
            output = output[:-1] + "\n"
        output = "".join([(line + (self.col-len(line))*" " + "\\\n") \
                          for line in output.splitlines()])
        with open(filename) as f:
            output += "    \"" + f.read().splitlines()[-1] + "\\r\\n\"\n"
        return output

    # Extract key or certificate from file.
    def extract_key(self, enctyp, name, filename, line_num):
        """ Depending on encoding and type it calls appriopriate
        function

        enctyp: (encoding , type)
        name: name of variable/macro
        filename: where data is
        line_num: line number
        """

        enc = enctyp[0]
        typ = enctyp[1]
        if enc not in ("string", "binary"):
            raise TypeEncodingException(enc, line_num)
        if typ not in ("macro", "variable"):
            raise TypeEncodingException(typ, line_num)

        output = ""
        if typ == "variable":
            if enc == "binary":
                output = self.type_var_bin(name, filename)
            elif enc == "string":
                output = self.type_var_string(name, filename)
        elif typ == "macro":
            if enc == "binary":
                output = self.type_macro_bin(name, filename)
            elif enc == "string":
                output = self.type_macro_string(name, filename)
        return output

    def update(self):
        """ Updates cert file using data given in comment
        sections. Location of certs.c file is hardcoded
        """
        tempf = tempfile.TemporaryFile(mode="w+")
        with open(self.certs, "r+") as old_f, open(tempf.name, "w+") as tmp:
            line_num = 1
            line = old_f.readline()
            while line:
                if re.fullmatch(r"^/\*\s*BEGIN FILE.*\*/$\n", line):
                    tmp.write(line)
                    args = re.fullmatch(r"^/\*\s*BEGIN FILE(.*)\*/$\n", line).group(1) \
                                                                             .strip()  \
                                                                             .split(" ")[0:4]
                    if len(args) != 4:
                        raise FormatException("beginline", line_num)
                    try:
                        add = self.extract_key((args[0], args[1]), args[2], args[3], line_num)
                    except IOError as er:
                        raise FormatException("nofile", line_num)
                    tmp.write(add)
                    line = old_f.readline()
                    line_num += 1
                    if not line:
                        raise FormatException("eof", -1)
                    while not re.fullmatch(r"^/\*\s*END FILE\s*\*/$\n", line):
                        if re.fullmatch(r"^/\*\s*BEGIN FILE.*\*/$\n", line):
                            raise FormatException("beginbegin", line_num)
                        line = old_f.readline()
                        line_num += 1
                        if not line:
                            raise FormatException("eof", -1)
                tmp.write(line)
                line = old_f.readline()
                line_num += 1
            tmp.seek(0)
            old_f.truncate(0)
            old_f.seek(0)
            old_f.write(tmp.read())

def run_main():
    if not os.path.exists("include/mbedtls"):
        print("Must be run from root")
        sys.exit(1)

    try:
        updater = CertUpdater()
        updater.update()
    except TypeEncodingException as ex:
        print(ex)
        sys.exit(1)
    except FormatException as ex:
        print(ex)
        sys.exit(1)

if __name__ == "__main__":
    run_main()
