#!/usr/bin/env python3
# Test suites code generator.
#
# Copyright (C) 2018, ARM Limited, All Rights Reserved
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
#
# This file is part of mbed TLS (https://tls.mbed.org)

"""
This script dynamically generates test suite code for Mbed TLS, by
taking following input files.

test_suite_xyz.function     -   Test suite functions file contains test
                                functions.
test_suite_xyz.data         -   Contains test case vectors.
main_test.function          -   Template to substitute generated test
                                functions, dispatch code, dependency
                                checking code etc.
platform .function          -   Platform specific initialization and
                                platform code.
helpers.function -              Common/reusable data and functions.
"""


import io
import os
import re
import sys
import argparse


BEGIN_HEADER_REGEX = '/\*\s*BEGIN_HEADER\s*\*/'
END_HEADER_REGEX = '/\*\s*END_HEADER\s*\*/'

BEGIN_SUITE_HELPERS_REGEX = '/\*\s*BEGIN_SUITE_HELPERS\s*\*/'
END_SUITE_HELPERS_REGEX = '/\*\s*END_SUITE_HELPERS\s*\*/'

BEGIN_DEP_REGEX = 'BEGIN_DEPENDENCIES'
END_DEP_REGEX = 'END_DEPENDENCIES'

BEGIN_CASE_REGEX = '/\*\s*BEGIN_CASE\s*(.*?)\s*\*/'
END_CASE_REGEX = '/\*\s*END_CASE\s*\*/'


class GeneratorInputError(Exception):
    """
    Exception to indicate error in the input files to this script.
    This includes missing patterns, test function names and other
    parsing errors.
    """
    pass


class FileWrapper(io.FileIO):
    """
    This class extends built-in io.FileIO class with attribute line_no,
    that indicates line number for the line that is read.
    """

    def __init__(self, file_name):
        """
        Instantiate the base class and initialize the line number to 0.

        :param file_name: File path to open.
        """
        super(FileWrapper, self).__init__(file_name, 'r')
        self.line_no = 0

    def __next__(self):
        """
        Python 2 iterator method. This method overrides base class's
        next method and extends the next method to count the line
        numbers as each line is read.

        It works for both Python 2 and Python 3 by checking iterator
        method name in the base iterator object.

        :return: Line read from file.
        """
        parent = super(FileWrapper, self)
        if hasattr(parent, '__next__'):
            line = parent.__next__() # Python 3
        else:
            line = parent.next() # Python 2
        if line:
            self.line_no += 1
            # Convert byte array to string with correct encoding and
            # strip any whitespaces added in the decoding process.
            return line.decode(sys.getdefaultencoding()).strip() + "\n"
        return None

    # Python 3 iterator method
    next = __next__


def split_dep(dep):
    """
    Split NOT character '!' from dependency. Used by gen_deps()

    :param dep: Dependency list
    :return: string tuple. Ex: ('!', MACRO) for !MACRO and ('', MACRO) for
             MACRO.
    """
    return ('!', dep[1:]) if dep[0] == '!' else ('', dep)


def gen_deps(deps):
    """
    Test suite data and functions specifies compile time dependencies.
    This function generates C preprocessor code from the input
    dependency list. Caller uses the generated preprocessor code to
    wrap dependent code.
    A dependency in the input list can have a leading '!' character
    to negate a condition. '!' is separated from the dependency using
    function split_dep() and proper preprocessor check is generated
    accordingly.

    :param deps: List of dependencies.
    :return: if defined and endif code with macro annotations for
             readability.
    """
    dep_start = ''.join(['#if %sdefined(%s)\n' % split_dep(x) for x in deps])
    dep_end = ''.join(['#endif /* %s */\n' % x for x in reversed(deps)])

    return dep_start, dep_end


def gen_deps_one_line(deps):
    """
    Similar to gen_deps() but generates dependency checks in one line.
    Useful for generating code with #else block.

    :param deps: List of dependencies.
    :return: ifdef code
    """
    defines = '#if ' if len(deps) else ''
    defines += ' && '.join(['%sdefined(%s)' % split_dep(x) for x in deps])
    return defines


def gen_function_wrapper(name, locals, args_dispatch):
    """
    Creates test function wrapper code. A wrapper has the code to
    unpack parameters from parameters[] array.

    :param name: Test function name
    :param locals: Local variables declaration code
    :param args_dispatch: List of dispatch arguments.
           Ex: ['(char *)params[0]', '*((int *)params[1])']
    :return: Test function wrapper.
    """
    # Then create the wrapper
    wrapper = '''
void {name}_wrapper( void ** params )
{{
{unused_params}{locals}
    {name}( {args} );
}}
'''.format(name=name,
           unused_params='' if args_dispatch else '    (void)params;\n',
           args=', '.join(args_dispatch),
           locals=locals)
    return wrapper


def gen_dispatch(name, deps):
    """
    Test suite code template main_test.function defines a C function
    array to contain test case functions. This function generates an
    initializer entry for a function in that array. The entry is
    composed of a compile time check for the test function
    dependencies. At compile time the test function is assigned when
    dependencies are met, else NULL is assigned.

    :param name: Test function name
    :param deps: List of dependencies
    :return: Dispatch code.
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


def parse_until_pattern(funcs_f, end_regex):
    """
    Matches pattern end_regex to the lines read from the file object.
    Returns the lines read until end pattern is matched.

    :param funcs_f: file object for .functions file
    :param end_regex: Pattern to stop parsing
    :return: Lines read before the end pattern
    """
    headers = '#line %d "%s"\n' % (funcs_f.line_no + 1, funcs_f.name)
    for line in funcs_f:
        if re.search(end_regex, line):
            break
        headers += line
    else:
        raise GeneratorInputError("file: %s - end pattern [%s] not found!" %
                                (funcs_f.name, end_regex))

    return headers


def parse_suite_deps(funcs_f):
    """
    Parses test suite dependencies specified at the top of a
    .function file, that starts with pattern BEGIN_DEPENDENCIES
    and end with END_DEPENDENCIES. Dependencies are specified
    after pattern 'depends_on:' and are delimited by ':'.

    :param funcs_f: file object for .functions file
    :return: List of test suite dependencies.
    """
    deps = []
    for line in funcs_f:
        m = re.search('depends_on\:(.*)', line.strip())
        if m:
            deps += [x.strip() for x in m.group(1).split(':')]
        if re.search(END_DEP_REGEX, line):
            break
    else:
        raise GeneratorInputError("file: %s - end dependency pattern [%s]"
                                " not found!" % (funcs_f.name, END_DEP_REGEX))

    return deps


def parse_function_deps(line):
    """
    Parses function dependencies, that are in the same line as
    comment BEGIN_CASE. Dependencies are specified after pattern
    'depends_on:' and are delimited by ':'.

    :param line: Line from .functions file that has dependencies.
    :return: List of dependencies.
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
    Parses test function signature for validation and generates
    a dispatch wrapper function that translates input test vectors
    read from the data file into test function arguments.

    :param line: Line from .functions file that has a function
                 signature.
    :return: function name, argument list, local variables for
             wrapper function and argument dispatch code.
    """
    args = []
    locals = ''
    args_dispatch = []
    # Check if the test function returns void.
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
            pointer_initializer = '(uint8_t *) params[%d]' % arg_idx
            len_initializer = '*( (uint32_t *) params[%d] )' % (arg_idx+1)
            locals += """    HexParam_t hex%d = {%s, %s};
""" % (arg_idx, pointer_initializer, len_initializer)

            args_dispatch.append('&hex%d' % arg_idx)
            arg_idx += 1
        else:
            raise ValueError("Test function arguments can only be 'int', "
                             "'char *' or 'HexParam_t'\n%s" % line)
        arg_idx += 1

    return name, args, locals, args_dispatch


def parse_function_code(funcs_f, deps, suite_deps):
    """
    Parses out a function from function file object and generates
    function and dispatch code.

    :param funcs_f: file object of the functions file.
    :param deps: List of dependencies
    :param suite_deps: List of test suite dependencies
    :return: Function name, arguments, function code and dispatch code.
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
        raise GeneratorInputError("file: %s - Test functions not found!" %
                                funcs_f.name)

    for line in funcs_f:
        if re.search(END_CASE_REGEX, line):
            break
        code += line
    else:
        raise GeneratorInputError("file: %s - end case pattern [%s] not "
                                "found!" % (funcs_f.name, END_CASE_REGEX))

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
    Parses a test_suite_xxx.function file and returns information
    for generating a C source file for the test suite.

    :param funcs_f: file object of the functions file.
    :return: List of test suite dependencies, test function dispatch
             code, function code and a dict with function identifiers
             and arguments info.
    """
    suite_headers = ''
    suite_helpers = ''
    suite_deps = []
    suite_functions = ''
    func_info = {}
    function_idx = 0
    dispatch_code = ''
    for line in funcs_f:
        if re.search(BEGIN_HEADER_REGEX, line):
            headers = parse_until_pattern(funcs_f, END_HEADER_REGEX)
            suite_headers += headers
        elif re.search(BEGIN_SUITE_HELPERS_REGEX, line):
            helpers = parse_until_pattern(funcs_f, END_SUITE_HELPERS_REGEX)
            suite_helpers += helpers
        elif re.search(BEGIN_DEP_REGEX, line):
            deps = parse_suite_deps(funcs_f)
            suite_deps += deps
        elif re.search(BEGIN_CASE_REGEX, line):
            deps = parse_function_deps(line)
            func_name, args, func_code, func_dispatch =\
                parse_function_code(funcs_f, deps, suite_deps)
            suite_functions += func_code
            # Generate dispatch code and enumeration info
            if func_name in func_info:
                raise GeneratorInputError(
                    "file: %s - function %s re-declared at line %d" % \
                    (funcs_f.name, func_name, funcs_f.line_no))
            func_info[func_name] = (function_idx, args)
            dispatch_code += '/* Function Id: %d */\n' % function_idx
            dispatch_code += func_dispatch
            function_idx += 1

    ifdef, endif = gen_deps(suite_deps)
    func_code = ifdef + suite_headers + suite_helpers + suite_functions + endif
    return suite_deps, dispatch_code, func_code, func_info


def escaped_split(str, ch):
    """
    Split str on character ch but ignore escaped \{ch}
    Since, return value is used to write back to the intermediate
    data file, any escape characters in the input are retained in the
    output.

    :param str: String to split
    :param ch: split character
    :return: List of splits
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
    Parses .data file for each test case name, test function name,
    test dependencies and test arguments. This information is
    correlated with the test functions file for generating an
    intermediate data file replacing the strings for test function
    names, dependencies and integer constant expressions with
    identifiers. Mainly for optimising space for on-target
    execution.

    :param data_f: file object of the data file.
    :return: Generator that yields test name, function name,
             dependency list and function argument list.
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
            if state == STATE_READ_ARGS:
                raise GeneratorInputError("[%s:%d] Newline before arguments. "
                                          "Test function and arguments "
                                          "missing for %s" %
                                          (data_f.name, data_f.line_no, name))
            continue

        if state == STATE_READ_NAME:
            # Read test name
            name = line
            state = STATE_READ_ARGS
        elif state == STATE_READ_ARGS:
            # Check dependencies
            m = re.search('depends_on\:(.*)', line)
            if m:
                deps = [x.strip() for x in m.group(1).split(':') if len(
                    x.strip())]
            else:
                # Read test vectors
                parts = escaped_split(line, ':')
                function = parts[0]
                args = parts[1:]
                yield name, function, deps, args
                deps = []
                state = STATE_READ_NAME
    if state == STATE_READ_ARGS:
        raise GeneratorInputError("[%s:%d] Newline before arguments. "
                                  "Test function and arguments missing for "
                                  "%s" % (data_f.name, data_f.line_no, name))


def gen_dep_check(dep_id, dep):
    """
    Generate code for checking dependency with the associated
    identifier.

    :param dep_id: Dependency identifier
    :param dep: Dependency macro
    :return: Dependency check code
    """
    if dep_id < 0:
        raise GeneratorInputError("Dependency Id should be a positive "
                                  "integer.")
    noT, dep = ('!', dep[1:]) if dep[0] == '!' else ('', dep)
    if len(dep) == 0:
        raise GeneratorInputError("Dependency should not be an empty string.")
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
    Generates code for evaluating an integer expression using
    associated expression Id.

    :param exp_id: Expression Identifier
    :param exp: Expression/Macro
    :return: Expression check code
    """
    if exp_id < 0:
        raise GeneratorInputError("Expression Id should be a positive "
                                  "integer.")
    if len(exp) == 0:
        raise GeneratorInputError("Expression should not be an empty string.")
    exp_code = '''
        case {exp_id}:
            {{
                *out_value = {expression};
            }}
            break;'''.format(exp_id=exp_id, expression=exp)
    return exp_code


def write_deps(out_data_f, test_deps, unique_deps):
    """
    Write dependencies to intermediate test data file, replacing
    the string form with identifiers. Also, generates dependency
    check code.

    :param out_data_f: Output intermediate data file
    :param test_deps: Dependencies
    :param unique_deps: Mutable list to track unique dependencies
           that are global to this re-entrant function.
    :return: returns dependency check code.
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
    Writes test parameters to the intermediate data file, replacing
    the string form with identifiers. Also, generates expression
    check code.

    :param out_data_f: Output intermediate data file
    :param test_args: Test parameters
    :param func_args: Function arguments
    :param unique_expressions: Mutable list to track unique
           expressions that are global to this re-entrant function.
    :return: Returns expression check code.
    """
    expression_code = ''
    for i in range(len(test_args)):
        typ = func_args[i]
        val = test_args[i]

        # check if val is a non literal int val (i.e. an expression)
        if typ == 'int' and not re.match('(\d+$)|((0x)?[0-9a-fA-F]+$)', val):
            typ = 'exp'
            if val not in unique_expressions:
                unique_expressions.append(val)
                # exp_id can be derived from len(). But for
                # readability and consistency with case of existing
                # let's use index().
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
    Generates preprocessor checks for test suite dependencies.

    :param suite_deps: Test suite dependencies read from the
            .functions file.
    :param dep_check_code: Dependency check code
    :param expression_code: Expression check code
    :return: Dependency and expression code guarded by test suite
             dependencies.
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
    This function reads test case name, dependencies and test vectors
    from the .data file. This information is correlated with the test
    functions file for generating an intermediate data file replacing
    the strings for test function names, dependencies and integer
    constant expressions with identifiers. Mainly for optimising
    space for on-target execution.
    It also generates test case dependency check code and expression
    evaluation code.

    :param data_f: Data file object
    :param out_data_f:Output intermediate data file
    :param func_info: Dict keyed by function and with function id
           and arguments info
    :param suite_deps: Test suite deps
    :return: Returns dependency and expression check code
    """
    unique_deps = []
    unique_expressions = []
    dep_check_code = ''
    expression_code = ''
    for test_name, function_name, test_deps, test_args in parse_test_data(
            data_f):
        out_data_f.write(test_name + '\n')

        # Write deps
        dep_check_code += write_deps(out_data_f, test_deps, unique_deps)

        # Write test function name
        test_function_name = 'test_' + function_name
        if test_function_name not in func_info:
            raise GeneratorInputError("Function %s not found!" %
                                      test_function_name)
        func_id, func_args = func_info[test_function_name]
        out_data_f.write(str(func_id))

        # Write parameters
        if len(test_args) != len(func_args):
            raise GeneratorInputError("Invalid number of arguments in test "
                                      "%s. See function %s signature." % (
                                      test_name, function_name))
        expression_code += write_parameters(out_data_f, test_args, func_args,
                                            unique_expressions)

        # Write a newline as test case separator
        out_data_f.write('\n')

    dep_check_code, expression_code = gen_suite_deps_checks(
        suite_deps, dep_check_code, expression_code)
    return dep_check_code, expression_code


def generate_code(funcs_file, data_file, template_file, platform_file,
                  helpers_file, suites_dir, c_file, out_data_file):
    """
    Generates C source code from test suite file, data file, common
    helpers file and platform file.

    :param funcs_file: Functions file object
    :param data_file: Data file object
    :param template_file: Template file object
    :param platform_file: Platform file object
    :param helpers_file: Helper functions file object
    :param suites_dir: Test suites dir
    :param c_file: Output C file object
    :param out_data_file: Output intermediate data file object
    :return:
    """
    for name, path in [('Functions file', funcs_file),
                       ('Data file', data_file),
                       ('Template file', template_file),
                       ('Platform file', platform_file),
                       ('Helpers code file', helpers_file),
                       ('Suites dir', suites_dir)]:
        if not os.path.exists(path):
            raise IOError("ERROR: %s [%s] not found!" % (name, path))

    snippets = {'generator_script' : os.path.basename(__file__)}

    # Read helpers
    with open(helpers_file, 'r') as help_f, open(platform_file, 'r') as \
            platform_f:
        snippets['test_common_helper_file'] = helpers_file
        snippets['test_common_helpers'] = help_f.read()
        snippets['test_platform_file'] = platform_file
        snippets['platform_code'] = platform_f.read().replace(
            'DATA_FILE', out_data_file.replace('\\', '\\\\')) # escape '\'

    # Function code
    with FileWrapper(funcs_file) as funcs_f, FileWrapper(data_file) as \
            data_f, open(out_data_file, 'w') as out_data_f:
        suite_deps, dispatch_code, func_code, func_info = parse_functions(
            funcs_f)
        snippets['functions_code'] = func_code
        snippets['dispatch_code'] = dispatch_code
        dep_check_code, expression_code = gen_from_test_data(
            data_f, out_data_f, func_info, suite_deps)
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
            # Update line number. +1 as #line directive sets next line number
            snippets['line_no'] = line_no + 1
            code = line.format(**snippets)
            c_f.write(code)
            line_no += 1


def check_cmd():
    """
    Command line parser.

    :return:
    """
    parser = argparse.ArgumentParser(
        description='Dynamically generate test suite code.')

    parser.add_argument("-f", "--functions-file",
                        dest="funcs_file",
                        help="Functions file",
                        metavar="FUNCTIONS_FILE",
                        required=True)

    parser.add_argument("-d", "--data-file",
                        dest="data_file",
                        help="Data file",
                        metavar="DATA_FILE",
                        required=True)

    parser.add_argument("-t", "--template-file",
                        dest="template_file",
                        help="Template file",
                        metavar="TEMPLATE_FILE",
                        required=True)

    parser.add_argument("-s", "--suites-dir",
                        dest="suites_dir",
                        help="Suites dir",
                        metavar="SUITES_DIR",
                        required=True)

    parser.add_argument("--helpers-file",
                        dest="helpers_file",
                        help="Helpers file",
                        metavar="HELPERS_FILE",
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
    out_data_file = os.path.join(args.out_dir, data_name + '.datax')

    out_c_file_dir = os.path.dirname(out_c_file)
    out_data_file_dir = os.path.dirname(out_data_file)
    for d in [out_c_file_dir, out_data_file_dir]:
        if not os.path.exists(d):
            os.makedirs(d)

    generate_code(args.funcs_file, args.data_file, args.template_file,
                  args.platform_file, args.helpers_file, args.suites_dir,
                  out_c_file, out_data_file)


if __name__ == "__main__":
    try:
        check_cmd()
    except GeneratorInputError as e:
        script_name = os.path.basename(sys.argv[0])
        print("%s: input error: %s" % (script_name, str(e)))
