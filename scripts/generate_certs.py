#!/usr/bin/env python3

import sys
import os
import re
import subprocess
import tempfile




class updaterCerts:

    def __init__(self):
        self.CERTS = "tests/src/certs.c"


    def type_var_bin(self,name,filename):
        output = "const unsigned char " + name + "[] = {\n"
        data = subprocess.run(["xxd","-i",filename],capture_output=True).stdout.decode("utf-8")
        output += '   ' + '   '.join(data.splitlines(keepends=True)[1:-2])
        output += "};\n"
        return output

    def type_var_string(self,name,filename):
        output = "const char " + name + "[] =\n"
        with open(filename) as f:
            for line in f.read().splitlines():
                output += "    \"" + line + "\\r\\n\"\n"
            output = output[:-1] + ";\n"
        return output

    def type_macro_bin(self,name,filename):
        output = "#define " + name + " {\n"
        data = subprocess.run(["xxd","-i",filename],capture_output=True).stdout.decode("utf-8")
        output += '  ' + '  '.join(data.splitlines(keepends=True)[1:-2])
        output = "".join([(line + (77-len(line))*" " + "\\\n") for line in output.splitlines()])
        output += "}\n"
        return output

    def type_macro_string(self,name,filename):
        output = "#define " + name + "\n"
        with open(filename) as f:
            for line in f.read().splitlines()[:-1]:
                output += "    \"" + line + "\\r\\n\"\n"
            output = output[:-1] + "\n"
        output = "".join([(line + (75-len(line))*" " + "\\\n") for line in output.splitlines()])
        with open(filename) as f:
            output += "    \"" + f.read().splitlines()[-1] + "\\r\\n\"\n"
        return output

    # Extract key or certificate from file.
    def extract_key(self,enc,typ,name,filename):
        if (enc != "string" and enc != "binary"):
            print("choose either string encoding or binary encoding")
            sys.exit(1)
        if (typ != "macro" and typ != "variable"):
            print("choose either macro or variable as a type")
            sys.exit(1)

        output = ""
        if (typ == "variable"):
            if (enc == "binary"):
                output = self.type_var_bin(name,filename)
            elif (enc == "string"):
                output = self.type_var_string(name,filename)
        elif (typ == "macro"):
            if (enc == "binary"):
                output = self.type_macro_bin(name,filename)
            elif (enc == "string"):
                output = self.type_macro_string(name,filename)
        return output

    # Update cert.c file using datas from tests/data_files
    def update(self):
        TEMPFILE = tempfile.TemporaryFile(mode="w+")
        with open(self.CERTS,"r+") as old_f, open(TEMPFILE.name,"w+") as tmp:
            line = old_f.readline()
            while line:
                if re.fullmatch("^/\*\s*BEGIN FILE.*\*/$\n",line):
                    tmp.write(line)
                    args = line.split(" ")[3:7]
                    add = self.extract_key(args[0],args[1],args[2],args[3])
                    tmp.write(add)
                    line = old_f.readline()
                    while not re.fullmatch("^/\*\s*END FILE\s*\*/$\n",line):
                        line = old_f.readline()
                tmp.write(line)
                line = old_f.readline()
            tmp.seek(0)
            old_f.truncate(0)
            final = tmp.read()
            old_f.seek(0)
            old_f.write(final)

def run_main():
    if not os.path.exists("include/mbedtls"):
       print("Must be run from root")
       sys.exit(2)

    updater = updaterCerts()
    updater.update()

if __name__ == "__main__":
    run_main()
