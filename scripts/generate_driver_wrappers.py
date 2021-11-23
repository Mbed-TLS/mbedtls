#!/usr/bin/env python3
"""This script is required for the auto generation of the
   psa_crypto_driver_wrappers.c file"""

import sys
import os
import jinja2

def render(template_path: str) -> str:
    environment = jinja2.Environment(
        loader=jinja2.FileSystemLoader(os.path.dirname(template_path)),
        keep_trailing_newline=True)
    template = environment.get_template(os.path.basename(template_path))
    return template.render()

N = len(sys.argv)
if N != 2:
# This is the Root directory.
    ROOT_DIR = ""
else:
# Set the root based on the argument passed.
    ROOT_DIR = sys.argv[1]

# Set template file name, output file name from the root directory
DRIVER_WRAPPER_TEMPLATE_FILENAME = ROOT_DIR +\
    "scripts/data_files/driver_templates/psa_crypto_driver_wrappers.conf"
DRIVER_WRAPPER_OUTPUT_FILENAME = ROOT_DIR + "library/psa_crypto_driver_wrappers.c"

# Render the template
RESULT = render(DRIVER_WRAPPER_TEMPLATE_FILENAME)

# Write output to file
OUT_FILE = open(DRIVER_WRAPPER_OUTPUT_FILENAME, "w")
OUT_FILE.write(RESULT)
OUT_FILE.close()
