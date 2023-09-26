#!/usr/bin/env python3

import subprocess
import sys
from types import FunctionType

BASH_COMPONENT_CODE = '''
global component_{0}
def component_{0}():
    component_proc = subprocess.Popen(['tests/scripts/all.sh', '{0}'], stdout=subprocess.PIPE)
    for line in component_proc.stdout:
        line = str(line, 'utf-8')
        print(line, end='')
'''

def import_bash_components_file(components_file):
    # Get a list of functions defined in the components file
    get_fns_cmd = ['/bin/bash', '-c',
                   'source {} && compgen -A function'.format(components_file)]

    function_list = subprocess.check_output(get_fns_cmd)
    function_list = str(function_list, 'utf-8').split()

    # Get the components
    component_names = filter(lambda x: x.startswith('component_'), function_list)
    # Remove 'component_' prefix
    component_names = list(map(lambda x: x[len('component_'):], component_names))

    for component in component_names:
        # Create a new python function that runs the component in all.sh
        exec(BASH_COMPONENT_CODE.format(component))


import_bash_components_file('tests/scripts/components.sh')

# Get all functions starting with 'component_'
components = dict(filter(lambda x: x[0].startswith('component_'), locals().items()))

if len(sys.argv) > 1:
    # Component names passed on the command line
    components_to_run = sys.argv[1:]
    component_fns = map(lambda x: 'component_' + x, components_to_run)
    for func in component_fns:
        if func in components:
            components[func]()
        else:
            print('Error: Component \'{}\' not found'.format(sys.argv[1]))
            sys.exit(1)
else:
    for component_name in components:
        components[component_name]()
