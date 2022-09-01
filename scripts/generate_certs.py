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
    """ Custom Excepion for file format """
    typ = ""
    line = 0

    def __init__(self, typ, line, *args):
        super().__init__(args)
        self.typ = typ
        self.line = line

    def __str__(self):
        ret = "In line " + str(self.line) + ", "
        if self.typ == "eof":
            ret += "reached end of file unexpectedly"
        elif self.typ == "begin-begin":
            ret += f"Encountered another Begin File line before End File"
        else:
            ret += "unknown format exception"
        return ret

class WrongParamException(Exception):
    """ Custom exception for wrong parameters in begin line"""
    def __init__(self, typ, tried, line, *args):
        super().__init__(args)
        self.typ = typ
        self.tried = tried
        self.line = line

    def __str__(self):
        ret = "In line " + str(self.line) + ", "
        if self.typ == "type":
            ret += self.tried + " is not valid type.(macro or variable)"
        elif self.typ == "encoding":
            ret += self.tried + " is not valid encoding.(string or binary)"
        elif self.typ == "nofile":
            ret += self.tried + " is not valid file path"
        elif self.typ == "param_num":
            ret += "wrong number of parameters"
        else:
            ret += "unknown param exception"
        return ret

class CertUpdater:
    """ Updater for certs.c"""
    col = 77
    file_cert = None
    tmp = None
    line_num = 0
    line = ""

    def __init__(self):
        """Instantiate the updater for certs.c

        certs: path to certs.c
        """
        self.file_cert = open("tests/src/certs.c", "r+")
        self.tmp = tempfile.TemporaryFile(mode="w+t")
        self.line_num = 0
        self.line = ""

    def __del__(self):
        self.file_cert.close()
        self.tmp.close()

    def read_line(self):
        self.line_num += 1
        self.line = self.file_cert.readline()

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
    def extract_key(self, enctyp, name, filename):
        """ Depending on encoding and type it calls appriopriate
        function

        enctyp: (encoding , type)
        name: name of variable/macro
        filename: where data is
        """

        enc = enctyp[0]
        typ = enctyp[1]
        if enc not in ("string", "binary"):
            raise WrongParamException("encoding", enc, self.line_num)
        if typ not in ("macro", "variable"):
            raise WrongParamException("type", typ, self.line_num)

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

    # This function is called when parser ecnounters header line for certificate.
    def deal_with_cert(self):
        """ It will deal with certificate header line accordingly
        """
        self.tmp.write(self.line)
        args = re.fullmatch(r"^/\*\s*BEGIN FILE(.*)\*/$\n", self.line).group(1) \
                                                                    .strip()  \
                                                                    .split(" ")[0:4]
        if len(args) != 4:
            raise WrongParamException("param_num", len(args), self.line_num)
        try:
            add = self.extract_key((args[0], args[1]), args[2], args[3])
        except IOError as er:
            raise WrongParamException("nofile", args[3], self.line_num)
        self.tmp.write(add)
        self.read_line()
        if not self.line:
            raise FormatException("eof", self.line_num)
        while not re.fullmatch(r"^/\*\s*END FILE\s*\*/$\n", self.line):
            if re.fullmatch(r"^/\*\s*BEGIN FILE.*\*/$\n", self.line):
                raise FormatException("begin-begin", self.line_num)
            self.read_line()
            if not self.line:
                raise FormatException("eof", self.line_num)

    def load_to_tmpfile(self):
        self.read_line()
        while self.line:
            if re.fullmatch(r"^/\*\s*BEGIN FILE.*\*/$\n", self.line):
                self.deal_with_cert()
            self.tmp.write(self.line)
            self.read_line()

    def update(self):
        """ Updates cert file using data given in comment
        sections. Location of certs.c file is hardcoded
        """
        self.load_to_tmpfile()
        self.file_cert.truncate(0)
        self.file_cert.seek(0)
        self.tmp.seek(0)
        self.file_cert.write(self.tmp.read())

def run_main():
    if not os.path.exists("include/mbedtls"):
        print("Must be run from root")
        sys.exit(1)

    try:
        updater = CertUpdater()
        updater.update()
    except WrongParamException as ex:
        print(ex)
        sys.exit(1)
    except FormatException as ex:
        print(ex)
        sys.exit(1)

if __name__ == "__main__":
    run_main()
