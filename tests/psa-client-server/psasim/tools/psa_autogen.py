#!/usr/bin/env python3
"""This hacky script generates a partition from a manifest file"""

# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

import json
import os
import sys
from os import listdir

if len(sys.argv) != 2:
    print("Usage: psa_autogen <manifest_file>")
    sys.exit(1)

FILENAME = str(sys.argv[1])


with open(str(FILENAME), "r") as read_file:
    data = json.load(read_file)
    FILENAME = os.path.basename(FILENAME)
    FILENAME = FILENAME.split('.')[0]
    print("Base filename is " + str(FILENAME))

    if str(data['psa_framework_version'] == "1.0"):
        entry_point = str(data['entry_point'])
        partition_name = str(data['name'])
        services = data['services']
        try:
            irqs = data['irqs']
        except KeyError:
            irqs = []

        try:
            os.mkdir("psa_manifest")
            print("Generating psa_manifest directory")
        except OSError:
            print ("PSA manifest directory already exists")

        man  = open(str("psa_manifest/" + FILENAME + ".h"), "w")
        pids = open("psa_manifest/pid.h", "a")
        sids = open("psa_manifest/sid.h", "a")

        if len(services) > 28:
           print ("Unsupported number of services")

        count = 4 # For creating SID array
        nsacl = "const int ns_allowed[32] = { "
        policy = "const int strict_policy[32] = { "
        qcode = "const char *psa_queues[] = { "
        versions = "const uint32_t versions[32] = { "
        queue_path = "psa_service_"
        start = False

        for x in range(0, count):
            qcode = qcode + "\"\", "
            nsacl = nsacl + "0, "
            policy = policy + "0, "
            versions = versions + "0, "

        # Go through all the services to make sid.h and pid.h
        for svc in services:
            man.write("#define {}_SIGNAL    0x{:08x}\n".format(svc['signal'], 2**count))
            sids.write("#define {}_SID    {}\n".format(svc['name'], svc['sid']))
            qcode = qcode + "\"" + queue_path + str(int(svc['sid'], 16)) + "\","
            ns_clients = svc['non_secure_clients']
            print(str(svc))
            if ns_clients == "true":
                nsacl = nsacl + "1, "
            else:
                nsacl = nsacl + "0, "
            try:
                versions = versions + str(svc['minor_version']) + ", "
            except KeyError:
                versions = versions + "1, "

            strict = 0
            try:
                if str(svc['minor_policy']).lower() == "strict":
                    strict = 1
                    policy = policy + "1, "
                else:
                    policy = policy + "0, "
            except KeyError:
                strict = 0
                policy = policy + "0, "

            count = count+1

        sigcode = ""
        handlercode = "void __sig_handler(int signo) {\n"
        irqcount = count
        for irq in irqs:
            man.write("#define {}    0x{:08x}\n".format(irq['signal'], 2**irqcount))
            sigcode = sigcode + "    signal({}, __sig_handler);\n".format(irq['source'])
            handlercode = handlercode + \
                          "    if (signo == {}) {{ raise_signal(0x{:08x}); }};\n".format(irq['source'], 2**irqcount)
            irqcount = irqcount+1

        handlercode = handlercode + "}\n"

        while (count < 32):
            qcode = qcode + "\"\", "
            nsacl = nsacl + "0, "
            versions = versions + "0, "
            policy = policy + "0, "
            count = count + 1

        qcode = qcode + "};\n"
        nsacl = nsacl + "};\n"
        versions = versions + "};\n"
        policy = policy + "};\n"

        pids.close()
        sids.close()
        man.close()

        symbols = []
        # Go through all the files in the current directory and look for the entrypoint

        for root, directories, filenames in os.walk('.'):
            for filename in filenames:

                if "psa_ff_bootstrap" in filename or filename == "psa_manifest":
                    continue

                try:
                    fullpath = os.path.join(root,filename)
                    with open(fullpath, encoding='utf-8') as currentFile:
                        text = currentFile.read()
                        if str(entry_point + "(") in text:
                            symbols.append(fullpath)
                except IOError:
                    print("Couldn't open " + filename)

                except UnicodeDecodeError:
                    pass

        print(str("Number of entrypoints detected: " + str(len(symbols))))
        if len(symbols) < 1:
            print("Couldn't find function " + entry_point)
            sys.exit(1)
        elif len(symbols) > 1:
            print("Duplicate entrypoint symbol detected: " + str(symbols))
            sys.exit(2)
        else:
            bs = open(str("psa_ff_bootstrap_" + str(partition_name) + ".c"), "w")
            bs.write("#include <psasim/init.h>\n")
            bs.write("#include \"" + symbols[0] + "\"\n")
            bs.write("#include <signal.h>\n\n")
            bs.write(qcode)
            bs.write(nsacl)
            bs.write(policy)
            bs.write(versions)
            bs.write("\n")
            bs.write(handlercode)
            bs.write("\n")
            bs.write("int main(int argc, char *argv[]) {\n")
            bs.write("    (void) argc;\n")
            bs.write(sigcode)
            bs.write("    __init_psasim(psa_queues, 32, ns_allowed, versions, strict_policy);\n")
            bs.write("    " + entry_point + "(argc, argv);\n}\n")
            bs.close()

            print("Success")
