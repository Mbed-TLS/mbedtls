"""
mbed TLS
Copyright (c) 2017 ARM Limited

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
 |-- mbedtls/
 |   |-- <test suite #1>/
 |   |    |-- main.c
 |   |    |-- *.data files
 |   ...
 |   |-- <test suite #n>/
 |   |    |-- main.c
 |   |    |-- *.data files
 |   |
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


class FileWrapper(file):
    """
    File wrapper class. Provides reading with line no. tracking. 
    """

    def __init__(self, file_name):
        """
        Init file handle.
        
        :param file_name: 
        """
        super(FileWrapper, self).__init__(file_name, 'r')
        self.line_no = 0

    def next(self):
        """
        Iterator return impl.
        :return: 
        """
        line = super(FileWrapper, self).next()
        if line:
            self.line_no += 1
        return line

    def readline(self, limit=0):
        """
        Wrap the base class readline.
        
        :param limit: 
        :return: 
        """
        return self.next()


def split_dep(dep):
    return ('!', dep[1:]) if dep[0] == '!' else ('', dep)


def gen_deps(deps):
    """
    Generates dependency i.e. if def and endif code

    :param deps:
    :return:
    """
    dep_start = ''.join(['#if %sdefined(%s)\n' % split_dep(x) for x in deps])
    dep_end = ''.join(['#endif /* %s */\n' % x for x in reversed(deps)])

    return dep_start, dep_end


def gen_deps_one_line(deps):
    """
    Generates dependency checks in one line. Useful for writing code in #else case.

    :param deps:
    :return:
    """
    defines = ('#if ' if len(deps) else '') + ' && '.join(['%sdefined(%s)' % split_dep(x) for x in deps])
    return defines


def gen_function_wrapper(name, locals, args_dispatch):
    """
    Creates test function code

    :param name:
    :param locals:
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
'''.format(name=name, unused_params='(void)params;' if len(args_dispatch) == 0 else '',
           args=', '.join(args_dispatch),
           locals=locals)
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


def parse_suite_headers(funcs_f):
    """
    Parses function headers.
    
    :param funcs_f: 
    :return: 
    """
    headers = '#line %d "%s"\n' % (funcs_f.line_no + 1, funcs_f.name)
    for line in funcs_f:
        if re.search(END_HEADER_REGEX, line):
            break
        headers += line
    else:
        raise InvalidFileFormat("file: %s - end header pattern [%s] not found!" % (funcs_f.name, END_HEADER_REGEX))

    return headers


def parse_suite_deps(funcs_f):
    """
    Parses function dependencies.
    
    :param funcs_f: 
    :return: 
    """
    deps = []
    for line in funcs_f:
        m = re.search('depends_on\:(.*)', line.strip())
        if m:
            deps += [x.strip() for x in m.group(1).split(':')]
        if re.search(END_DEP_REGEX, line):
            break
    else:
        raise InvalidFileFormat("file: %s - end dependency pattern [%s] not found!" % (funcs_f.name, END_DEP_REGEX))

    return deps


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
            deps = [x.strip() for x in m.group(1).strip().split(':')]
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
            raise ValueError("Test function arguments can only be 'int', 'char *' or 'HexParam_t'\n%s" % line)
        arg_idx += 1

    return name, args, locals, args_dispatch


def parse_function_code(funcs_f, deps, suite_deps):
    """
    
    :param line_no: 
    :param funcs_f: 
    :param deps:
    :param suite_deps:
    :return: 
    """
    code = '#line %d "%s"\n' % (funcs_f.line_no + 1, funcs_f.name)
    for line in funcs_f:
        # Check function signature
        m = re.match('.*?\s+(\w+)\s*\(', line, re.I)
        if m:
            # check if we have full signature i.e. split in more lines
            if not re.match('.*\)', line):
                for lin in funcs_f:
                    line += lin
                    if re.search('.*?\)', line):
                        break
            name, args, locals, args_dispatch = parse_function_signature(line)
            code += line.replace(name, 'test_' + name)
            name = 'test_' + name
            break
    else:
        raise InvalidFileFormat("file: %s - Test functions not found!" % funcs_f.name)

    for line in funcs_f:
        if re.search(END_CASE_REGEX, line):
            break
        code += line
    else:
        raise InvalidFileFormat("file: %s - end case pattern [%s] not found!" % (funcs_f.name, END_CASE_REGEX))

    # Add exit label if not present
    if code.find('exit:') == -1:
        s = code.rsplit('}', 1)
        if len(s) == 2:
            code = """exit:
    ;;
}""".join(s)

    code += gen_function_wrapper(name, locals, args_dispatch)
    ifdef, endif = gen_deps(deps)
    dispatch_code = gen_dispatch(name, suite_deps + deps)
    return name, args, ifdef + code + endif, dispatch_code


def parse_functions(funcs_f):
    """
    Returns functions code pieces
    
    :param funcs_f: 
    :return:
    """
    suite_headers = ''
    suite_deps = []
    suite_functions = ''
    func_info = {}
    function_idx = 0
    dispatch_code = ''
    for line in funcs_f:
        if re.search(BEGIN_HEADER_REGEX, line):
            headers = parse_suite_headers(funcs_f)
            suite_headers += headers
        elif re.search(BEGIN_DEP_REGEX, line):
            deps = parse_suite_deps(funcs_f)
            suite_deps += deps
        elif re.search(BEGIN_CASE_REGEX, line):
            deps = parse_function_deps(line)
            func_name, args, func_code, func_dispatch = parse_function_code(funcs_f, deps, suite_deps)
            suite_functions += func_code
            # Generate dispatch code and enumeration info
            assert func_name not in func_info, "file: %s - function %s re-declared at line %d" % \
                                               (funcs_f.name, func_name, funcs_f.line_no)
            func_info[func_name] = (function_idx, args)
            dispatch_code += '/* Function Id: %d */\n' % function_idx
            dispatch_code += func_dispatch
            function_idx += 1

    ifdef, endif = gen_deps(suite_deps)
    func_code = ifdef + suite_headers + suite_functions + endif
    return suite_deps, dispatch_code, func_code, func_info


def escaped_split(str, ch):
    """
    Split str on character ch but ignore escaped \{ch}
    Since return value is used to write back to the intermediate data file. 
    Any escape characters in the input are retained in the output.

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


def parse_test_data(data_f, debug=False):
    """
    Parses .data file
    
    :param data_f: 
    :return: 
    """
    STATE_READ_NAME = 0
    STATE_READ_ARGS = 1
    state = STATE_READ_NAME
    deps = []
    name = ''
    for line in data_f:
        line = line.strip()
        if len(line) and line[0] == '#': # Skip comments
            continue

        # Blank line indicates end of test
        if len(line) == 0:
            assert state != STATE_READ_ARGS, "Newline before arguments. " \
                                                 "Test function and arguments missing for %s" % name
            continue

        if state == STATE_READ_NAME:
            # Read test name
            name = line
            state = STATE_READ_ARGS
        elif state == STATE_READ_ARGS:
            # Check dependencies
            m = re.search('depends_on\:(.*)', line)
            if m:
                deps = [x.strip() for x in m.group(1).split(':') if len(x.strip())]
            else:
                # Read test vectors
                parts = escaped_split(line, ':')
                function = parts[0]
                args = parts[1:]
                yield name, function, deps, args
                deps = []
                state = STATE_READ_NAME
    assert state != STATE_READ_ARGS, "Newline before arguments. " \
                                     "Test function and arguments missing for %s" % name


def gen_dep_check(dep_id, dep):
    """
    Generate code for the dependency.
    
    :param dep_id: 
    :param dep: 
    :return: 
    """
    assert dep_id > -1, "Dependency Id should be a positive integer."
    noT, dep = ('!', dep[1:]) if dep[0] == '!' else ('', dep)
    assert len(dep) > 0, "Dependency should not be an empty string."
    dep_check = '''
        case {id}:
            {{
#if {noT}defined({macro})
                ret = 0;
#else
                ret = -2;
#endif
            }}
            break;'''.format(noT=noT, macro=dep, id=dep_id)
    return dep_check


def gen_expression_check(exp_id, exp):
    """
    Generates code for expression check
    
    :param exp_id: 
    :param exp: 
    :return: 
    """
    assert exp_id > -1, "Expression Id should be a positive integer."
    assert len(exp) > 0, "Expression should not be an empty string."
    exp_code = '''
        case {exp_id}:
            {{
                *out_value = {expression};
            }}
            break;'''.format(exp_id=exp_id, expression=exp)
    return exp_code


def write_deps(out_data_f, test_deps, unique_deps):
    """
    Write dependencies to intermediate test data file.
    It also returns dependency check code.
      
    :param out_data_f:
    :param dep: 
    :param unique_deps: 
    :return: 
    """
    dep_check_code = ''
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
    return dep_check_code


def write_parameters(out_data_f, test_args, func_args, unique_expressions):
    """
    Writes test parameters to the intermediate data file.
    Also generates expression code.
     
    :param out_data_f: 
    :param test_args: 
    :param func_args:
    :param unique_expressions: 
    :return: 
    """
    expression_code = ''
    for i in xrange(len(test_args)):
        typ = func_args[i]
        val = test_args[i]

        # check if val is a non literal int val
        if typ == 'int' and not re.match('(\d+$)|((0x)?[0-9a-fA-F]+$)', val):  # its an expression
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
    out_data_f.write('\n')
    return expression_code


def gen_suite_deps_checks(suite_deps, dep_check_code, expression_code):
    """
    Adds preprocessor checks for test suite dependencies.
    
    :param suite_deps: 
    :param dep_check_code: 
    :param expression_code: 
    :return: 
    """
    if len(suite_deps):
        ifdef = gen_deps_one_line(suite_deps)
        dep_check_code = '''
{ifdef}
{code}
#endif
'''.format(ifdef=ifdef, code=dep_check_code)
        expression_code = '''
{ifdef}
{code}
#endif
'''.format(ifdef=ifdef, code=expression_code)
    return dep_check_code, expression_code


def gen_from_test_data(data_f, out_data_f, func_info, suite_deps):
    """
    Generates dependency checks, expression code and intermediate data file from test data file.
    
    :param data_f: 
    :param out_data_f:
    :param func_info: 
    :param suite_deps:
    :return: 
    """
    unique_deps = []
    unique_expressions = []
    dep_check_code = ''
    expression_code = ''
    for test_name, function_name, test_deps, test_args in parse_test_data(data_f):
        out_data_f.write(test_name + '\n')

        # Write deps
        dep_check_code += write_deps(out_data_f, test_deps, unique_deps)

        # Write test function name
        test_function_name = 'test_' + function_name
        assert test_function_name in func_info, "Function %s not found!" % test_function_name
        func_id, func_args = func_info[test_function_name]
        out_data_f.write(str(func_id))

        # Write parameters
        assert len(test_args) == len(func_args), \
            "Invalid number of arguments in test %s. See function %s signature." % (test_name, function_name)
        expression_code += write_parameters(out_data_f, test_args, func_args, unique_expressions)

        # Write a newline as test case separator
        out_data_f.write('\n')

    dep_check_code, expression_code = gen_suite_deps_checks(suite_deps, dep_check_code, expression_code)
    return dep_check_code, expression_code


def generate_code(funcs_file, data_file, template_file, platform_file, help_file, suites_dir, c_file, out_data_file):
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
    with FileWrapper(funcs_file) as funcs_f, open(data_file, 'r') as data_f, open(out_data_file, 'w') as out_data_f:
        suite_deps, dispatch_code, func_code, func_info = parse_functions(funcs_f)
        snippets['functions_code'] = func_code
        snippets['dispatch_code'] = dispatch_code
        dep_check_code, expression_code = gen_from_test_data(data_f, out_data_f, func_info, suite_deps)
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

    generate_code(args.funcs_file, args.data_file, args.template_file, args.platform_file,
                  args.help_file, args.suites_dir, out_c_file, out_data_file)


if __name__ == "__main__":
    check_cmd()
