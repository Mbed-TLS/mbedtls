"""
mbed SDK
Copyright (c) 2017-2018 ARM Limited

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import os
import re
import argparse
import shutil


"""
Generates code in following structure.

<output dir>/
|-- host_tests/
|   |-- mbedtls_test.py
|   |-- suites/
|   |   |-- *.data files
|   |-- mbedtls/
|   |   |-- <test suite #1>/
|   |   |    |-- main.c
|   |   ...
|   |   |-- <test suite #n>/
|   |   |    |-- main.c
|   |   |
"""


BEGIN_HEADER_REGEX = '/\*\s*BEGIN_HEADER\s*\*/'
END_HEADER_REGEX = '/\*\s*END_HEADER\s*\*/'

BEGIN_DEP_REGEX = 'BEGIN_DEPENDENCIES'
END_DEP_REGEX = 'END_DEPENDENCIES'

BEGIN_CASE_REGEX = '/\*\s*BEGIN_CASE\s*(.*?)\s*\*/'
END_CASE_REGEX = '/\*\s*END_CASE\s*\*/'


class InvalidFileFormat(Exception):
    """
    Exception to indicate invalid file format. 
    """
    pass


def gen_deps(deps):
    """
    Generates dependency i.e. if def and endif code

    :param deps:
    :return:
    """
    dep_start = ''
    dep_end = ''
    for dep in deps:
        if dep[0] == '!':
            noT = '!'
            dep = dep[1:]
        else:
            noT = ''
        dep_start += '#if %sdefined(%s)\n' % (noT, dep)
        dep_end = '#endif /* %s%s */\n' % (noT, dep) + dep_end
    return dep_start, dep_end


def gen_deps_one_line(deps):
    """
    Generates dependency checks in one line. Useful for writing code in #else case.

    :param deps:
    :return:
    """
    defines = []
    for dep in deps:
        if dep[0] == '!':
            noT = '!'
            dep = dep[1:]
        else:
            noT = ''
        defines.append('%sdefined(%s)' % (noT, dep))
    return '#if ' + ' && '.join(defines)


def gen_function_wrapper(name, args_dispatch):
    """
    Creates test function code

    :param name:
    :param args_dispatch:
    :return:
    """
    # Then create the wrapper
    wrapper = '''
void {name}_wrapper( void ** params )
{{
    {unused_params}
{locals}
    {name}( {args} );
}}
'''.format(name=name, unused_params='(void)params;' if len(args_dispatch[1]) == 0 else '',
           args=', '.join(args_dispatch[1]),
           locals=args_dispatch[0])
    return wrapper


def gen_dispatch(name, deps):
    """
    Generates dispatch condition for the functions.

    :param name:
    :param deps:
    :return:
    """
    if len(deps):
        ifdef = gen_deps_one_line(deps)
        dispatch_code = '''
{ifdef}
    {name}_wrapper,
#else
    NULL,
#endif
'''.format(ifdef=ifdef, name=name)
    else:
        dispatch_code = '''
    {name}_wrapper,
'''.format(name=name)

    return dispatch_code


def parse_suite_headers(line_no, funcs_f):
    """
    Parses function headers.
    
    :param line_no:
    :param funcs_f: 
    :return: 
    """
    headers = '#line %d "%s"\n' % (line_no + 1, funcs_f.name)
    for line in funcs_f:
        line_no += 1
        if re.search(END_HEADER_REGEX, line):
            break
        headers += line
    else:
        raise InvalidFileFormat("file: %s - end header pattern [%s] not found!" % (funcs_f.name, END_HEADER_REGEX))

    return line_no, headers


def parse_suite_deps(line_no, funcs_f):
    """
    Parses function dependencies.
    
    :param line_no:
    :param funcs_f: 
    :return: 
    """
    deps = []
    for line in funcs_f:
        line_no += 1
        m = re.search('depends_on\:(.*)', line.strip())
        if m:
            deps += [x.strip() for x in m.group(1).split(':')]
        if re.search(END_DEP_REGEX, line):
            break
    else:
        raise InvalidFileFormat("file: %s - end dependency pattern [%s] not found!" % (funcs_f.name, END_DEP_REGEX))

    return line_no, deps


def parse_function_deps(line):
    """
    
    :param line: 
    :return: 
    """
    deps = []
    m = re.search(BEGIN_CASE_REGEX, line)
    dep_str = m.group(1)
    if len(dep_str):
        m = re.search('depends_on:(.*)', dep_str)
        if m:
            deps = m.group(1).strip().split(':')
    return deps


def parse_function_signature(line):
    """
    Parsing function signature
    
    :param line: 
    :return: 
    """
    args = []
    locals = ''
    args_dispatch = []
    m = re.search('\s*void\s+(\w+)\s*\(', line, re.I)
    if not m:
        raise ValueError("Test function should return 'void'\n%s" % line)
    name = m.group(1)
    line = line[len(m.group(0)):]
    arg_idx = 0
    for arg in line[:line.find(')')].split(','):
        arg = arg.strip()
        if arg == '':
            continue
        if re.search('int\s+.*', arg.strip()):
            args.append('int')
            args_dispatch.append('*( (int *) params[%d] )' % arg_idx)
        elif re.search('char\s*\*\s*.*', arg.strip()):
            args.append('char*')
            args_dispatch.append('(char *) params[%d]' % arg_idx)
        elif re.search('HexParam_t\s*\*\s*.*', arg.strip()):
            args.append('hex')
            # create a structure
            locals += """    HexParam_t hex%d = {%s, %s};
""" % (arg_idx, '(uint8_t *) params[%d]' % arg_idx, '*( (uint32_t *) params[%d] )' % (arg_idx + 1))

            args_dispatch.append('&hex%d' % arg_idx)
            arg_idx += 1
        else:
            raise ValueError("Test function arguments can only be 'int' or 'char *'\n%s" % line)
        arg_idx += 1

    return name, args, (locals, args_dispatch)


def parse_function_code(line_no, funcs_f, deps, suite_deps):
    """
    
    :param line_no: 
    :param funcs_f: 
    :param deps:
    :param suite_deps:
    :return: 
    """
    code = '#line %d "%s"\n' % (line_no + 1, funcs_f.name)
    for line in funcs_f:
        line_no += 1
        # Check function signature
        m = re.match('.*?\s+(\w+)\s*\(', line, re.I)
        if m:
            # check if we have full signature i.e. split in more lines
            if not re.match('.*\)', line):
                for lin in funcs_f:
                    line += lin
                    line_no += 1
                    if re.search('.*?\)', line):
                        break
            name, args, args_dispatch = parse_function_signature(line)
            code += line.replace(name, 'test_' + name)
            name = 'test_' + name
            break
    else:
        raise InvalidFileFormat("file: %s - Test functions not found!" % funcs_f.name)

    for line in funcs_f:
        line_no += 1
        if re.search(END_CASE_REGEX, line):
            break
        code += line
    else:
        raise InvalidFileFormat("file: %s - end case pattern [%s] not found!" % (funcs_f.name, END_CASE_REGEX))

    # Add exit label if not present
    if code.find('exit:') == -1:
        s = code.rsplit('}', 1)
        if len(s) == 2:
            code = """
exit:
    ;;
}
""".join(s)

    code += gen_function_wrapper(name, args_dispatch)
    ifdef, endif = gen_deps(deps)
    dispatch_code = gen_dispatch(name, suite_deps + deps)
    return line_no, name, args, ifdef + code + endif, dispatch_code


def parse_functions(funcs_f):
    """
    Returns functions code pieces
    
    :param funcs_f: 
    :return:
    """
    line_no = 0
    suite_headers = ''
    suite_deps = []
    suite_functions = ''
    func_info = {}
    function_idx = 0
    dispatch_code = ''
    for line in funcs_f:
        line_no += 1
        if re.search(BEGIN_HEADER_REGEX, line):
            line_no, headers = parse_suite_headers(line_no, funcs_f)
            suite_headers += headers
        elif re.search(BEGIN_DEP_REGEX, line):
            line_no, deps = parse_suite_deps(line_no, funcs_f)
            suite_deps += deps
        elif re.search(BEGIN_CASE_REGEX, line):
            deps = parse_function_deps(line)
            line_no, func_name, args, func_code, func_dispatch = parse_function_code(line_no, funcs_f, deps, suite_deps)
            suite_functions += func_code
            # Generate dispatch code and enumeration info
            assert func_name not in func_info, "file: %s - function %s re-declared at line %d" % \
                                               (funcs_f.name, func_name, line_no)
            func_info[func_name] = (function_idx, args)
            dispatch_code += '/* Function Id: %d */\n' % function_idx
            dispatch_code += func_dispatch
            function_idx += 1

    ifdef, endif = gen_deps(suite_deps)
    func_code = ifdef + suite_functions + endif
    return dispatch_code, suite_headers, func_code, func_info


def escaped_split(str, ch):
    """
    Split str on character ch but ignore escaped \{ch}

    :param str:
    :param ch:
    :return:
    """
    if len(ch) > 1:
        raise ValueError('Expected split character. Found string!')
    out = []
    part = ''
    escape = False
    for i in range(len(str)):
        if not escape and str[i] == ch:
            out.append(part)
            part = ''
        else:
            part += str[i]
            escape = not escape and str[i] == '\\'
    if len(part):
        out.append(part)
    return out


def parse_test_data(data_f):
    """
    Parses .data file
    
    :param data_f: 
    :return: 
    """
    STATE_READ_NAME = 0
    STATE_READ_ARGS = 1
    state = STATE_READ_NAME
    deps = []

    for line in data_f:
        line = line.strip()
        if len(line) and line[0] == '#': # Skip comments
            continue

        # skip blank lines
        if len(line) == 0:
            continue

        if state == STATE_READ_NAME:
            # Read test name
            name = line
            state = STATE_READ_ARGS
        elif state == STATE_READ_ARGS:
            # Check dependencies
            m = re.search('depends_on\:(.*)', line)
            if m:
                deps = m.group(1).split(':')
            else:
                # Read test vectors
                parts = escaped_split(line, ':')
                function = parts[0]
                args = parts[1:]
                yield name, function, deps, args
                deps = []
                state = STATE_READ_NAME


def gen_dep_check(dep_id, dep):
    """
    Generate code for the dependency.
    
    :param dep_id: 
    :param dep: 
    :return: 
    """
    if dep[0] == '!':
        noT = '!'
        dep = dep[1:]
    else:
        noT = ''
    dep_check = '''
if ( dep_id == {id} )
{{
#if {noT}defined({macro})
    return( DEPENDENCY_SUPPORTED );
#else
    return( DEPENDENCY_NOT_SUPPORTED );
#endif
}}
else
'''.format(noT=noT, macro=dep, id=dep_id)

    return dep_check


def gen_expression_check(exp_id, exp):
    """
    Generates code for expression check
    
    :param exp_id: 
    :param exp: 
    :return: 
    """
    exp_code = '''
if ( exp_id == {exp_id} )
{{
    *out_value = {expression};
}}
else
'''.format(exp_id=exp_id, expression=exp)
    return exp_code


def gen_from_test_data(data_f, out_data_f, func_info):
    """
    Generates dependency checks, expression code and intermediate data file from test data file.
    
    :param data_f: 
    :param out_data_f:
    :param func_info: 
    :return: 
    """
    unique_deps = []
    unique_expressions = []
    dep_check_code = ''
    expression_code = ''
    for test_name, function_name, test_deps, test_args in parse_test_data(data_f):
        out_data_f.write(test_name + '\n')

        func_id, func_args = func_info['test_' + function_name]
        if len(test_deps):
            out_data_f.write('depends_on')
            for dep in test_deps:
                if dep not in unique_deps:
                    unique_deps.append(dep)
                    dep_id = unique_deps.index(dep)
                    dep_check_code += gen_dep_check(dep_id, dep)
                else:
                    dep_id = unique_deps.index(dep)
                out_data_f.write(':' + str(dep_id))
            out_data_f.write('\n')

        assert len(test_args) == len(func_args), \
            "Invalid number of arguments in test %s. See function %s signature." % (test_name, function_name)
        out_data_f.write(str(func_id))
        for i in xrange(len(test_args)):
            typ = func_args[i]
            val = test_args[i]

            # check if val is a non literal int val
            if typ == 'int' and not re.match('\d+', val):  # its an expression # FIXME: Handle hex format. Tip: instead try converting int(str, 10) and int(str, 16)
                typ = 'exp'
                if val not in unique_expressions:
                    unique_expressions.append(val)
                    # exp_id can be derived from len(). But for readability and consistency with case of existing let's
                    # use index().
                    exp_id = unique_expressions.index(val)
                    expression_code += gen_expression_check(exp_id, val)
                    val = exp_id
                else:
                    val = unique_expressions.index(val)
            out_data_f.write(':' + typ + ':' + str(val))
        out_data_f.write('\n\n')

    # void unused params
    if len(dep_check_code) == 0:
        dep_check_code = '(void) dep_id;\n'
    if len(expression_code) == 0:
        expression_code = '(void) exp_id;\n'
        expression_code += '(void) out_value;\n'

    return dep_check_code, expression_code


def gen_mbed_code(funcs_file, data_file, template_file, platform_file, help_file, suites_dir, c_file, out_data_file):
    """
    Generate mbed-os test code.

    :param funcs_file:
    :param dat  a_file:
    :param template_file:
    :param platform_file:
    :param help_file:
    :param suites_dir:
    :param c_file:
    :param out_data_file:
    :return:
    """
    for name, path in [('Functions file', funcs_file),
                       ('Data file', data_file),
                       ('Template file', template_file),
                       ('Platform file', platform_file),
                       ('Help code file', help_file),
                       ('Suites dir', suites_dir)]:
        if not os.path.exists(path):
            raise IOError("ERROR: %s [%s] not found!" % (name, path))

    snippets = {'generator_script' : os.path.basename(__file__)}

    # Read helpers
    with open(help_file, 'r') as help_f, open(platform_file, 'r') as platform_f:
        snippets['test_common_helper_file'] = help_file
        snippets['test_common_helpers'] = help_f.read()
        snippets['test_platform_file'] = platform_file
        snippets['platform_code'] = platform_f.read().replace('DATA_FILE',
                                                              out_data_file.replace('\\', '\\\\')) # escape '\'

    # Function code
    with open(funcs_file, 'r') as funcs_f, open(data_file, 'r') as data_f, open(out_data_file, 'w') as out_data_f:
        dispatch_code, func_headers, func_code, func_info = parse_functions(funcs_f)
        snippets['function_headers'] = func_headers
        snippets['functions_code'] = func_code
        snippets['dispatch_code'] = dispatch_code
        dep_check_code, expression_code = gen_from_test_data(data_f, out_data_f, func_info)
        snippets['dep_check_code'] = dep_check_code
        snippets['expression_code'] = expression_code

    snippets['test_file'] = c_file
    snippets['test_main_file'] = template_file
    snippets['test_case_file'] = funcs_file
    snippets['test_case_data_file'] = data_file
    # Read Template
    # Add functions
    #
    with open(template_file, 'r') as template_f, open(c_file, 'w') as c_f:
        line_no = 1
        for line in template_f.readlines():
            snippets['line_no'] = line_no + 1 # Increment as it sets next line number
            code = line.format(**snippets)
            c_f.write(code)
            line_no += 1


def check_cmd():
    """
    Command line parser.

    :return:
    """
    parser = argparse.ArgumentParser(description='Generate code for mbed-os tests.')

    parser.add_argument("-f", "--functions-file",
                        dest="funcs_file",
                        help="Functions file",
                        metavar="FUNCTIONS",
                        required=True)

    parser.add_argument("-d", "--data-file",
                        dest="data_file",
                        help="Data file",
                        metavar="DATA",
                        required=True)

    parser.add_argument("-t", "--template-file",
                        dest="template_file",
                        help="Template file",
                        metavar="TEMPLATE",
                        required=True)

    parser.add_argument("-s", "--suites-dir",
                        dest="suites_dir",
                        help="Suites dir",
                        metavar="SUITES",
                        required=True)

    parser.add_argument("--help-file",
                        dest="help_file",
                        help="Help file",
                        metavar="HELPER",
                        required=True)

    parser.add_argument("-p", "--platform-file",
                        dest="platform_file",
                        help="Platform code file",
                        metavar="PLATFORM_FILE",
                        required=True)

    parser.add_argument("-o", "--out-dir",
                        dest="out_dir",
                        help="Dir where generated code and scripts are copied",
                        metavar="OUT_DIR",
                        required=True)

    args = parser.parse_args()

    data_file_name = os.path.basename(args.data_file)
    data_name = os.path.splitext(data_file_name)[0]

    out_c_file = os.path.join(args.out_dir, data_name + '.c')
    out_data_file = os.path.join(args.out_dir, data_file_name)

    out_c_file_dir = os.path.dirname(out_c_file)
    out_data_file_dir = os.path.dirname(out_data_file)
    for d in [out_c_file_dir, out_data_file_dir]:
        if not os.path.exists(d):
            os.makedirs(d)

    gen_mbed_code(args.funcs_file, args.data_file, args.template_file, args.platform_file,
                  args.help_file, args.suites_dir, out_c_file, out_data_file)


if __name__ == "__main__":
    check_cmd()
