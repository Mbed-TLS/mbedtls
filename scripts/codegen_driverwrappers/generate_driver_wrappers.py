#!/usr/bin/env python3

import sys
import json
import os
import jinja2

def render(tpl_path):
    path, filename = os.path.split(tpl_path)
    return jinja2.Environment(
        loader=jinja2.FileSystemLoader(path or './'),
        keep_trailing_newline=True,
    ).get_template(filename).render()

n = len(sys.argv)
if ( n != 3 ):
    sys.exit("The template file name and output file name are expected as arguments")
# set template file name, output file name
driver_wrapper_template_filename = sys.argv[1]
driver_wrapper_output_filename = sys.argv[2]

# render the template
result = render(driver_wrapper_template_filename)

# write output to file
outFile = open(driver_wrapper_output_filename,"w")
outFile.write(result)
outFile.close()
