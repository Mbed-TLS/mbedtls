#!/usr/bin/env python3
'''Test the program psa_constant_names.
Gather constant names from header files and test cases. Compile a C program
to print out their numerical values, feed these numerical values to
psa_constant_names, and check that the output is the original name.
Return 0 if all test cases pass, 1 if the output was not always as expected,
or 1 (with a Python backtrace) if there was an operational error.'''

import argparse
import itertools
import os
import platform
import re
import subprocess
import sys
import tempfile

class ReadFileLineException(Exception):
    def __init__(self, filename, line_number):
        message = 'in {} at {}'.format(filename, line_number)
        super(ReadFileLineException, self).__init__(message)
        self.filename = filename
        self.line_number = line_number

class read_file_lines:
    '''Context manager to read a text file line by line.
with read_file_lines(filename) as lines:
    for line in lines:
        process(line)
is equivalent to
with open(filename, 'r') as input_file:
    for line in input_file:
        process(line)
except that if process(line) raises an exception, then the read_file_lines
snippet annotates the exception with the file name and line number.'''
    def __init__(self, filename):
        self.filename = filename
        self.line_number = 'entry'
    def __enter__(self):
        self.generator = enumerate(open(self.filename, 'r'))
        return self
    def __iter__(self):
        for line_number, content in self.generator:
            self.line_number = line_number
            yield content
        self.line_number = 'exit'
    def __exit__(self, type, value, traceback):
        if type is not None:
            raise ReadFileLineException(self.filename, self.line_number) \
                from value

class Inputs:
    '''Accumulate information about macros to test.
This includes macro names as well as information about their arguments
when applicable.'''
    def __init__(self):
        # Sets of names per type
        self.statuses = set(['PSA_SUCCESS'])
        self.algorithms = set(['0xffffffff'])
        self.ecc_curves = set(['0xffff'])
        self.key_types = set(['0xffffffff'])
        self.key_usage_flags = set(['0x80000000'])
        # Hard-coded value for unknown algorithms
        self.hash_algorithms = set(['0x010000fe'])
        self.mac_algorithms = set(['0x02ff00ff'])
        self.kdf_algorithms = set(['0x300000ff', '0x310000ff'])
        # For AEAD algorithms, the only variability is over the tag length,
        # and this only applies to known algorithms, so don't test an
        # unknown algorithm.
        self.aead_algorithms = set()
        # Identifier prefixes
        self.table_by_prefix = {
            'ERROR': self.statuses,
            'ALG': self.algorithms,
            'CURVE': self.ecc_curves,
            'KEY_TYPE': self.key_types,
            'KEY_USAGE': self.key_usage_flags,
        }
        # macro name -> list of argument names
        self.argspecs = {}
        # argument name -> list of values
        self.arguments_for = {
            'mac_length': ['1', '63'],
            'tag_length': ['1', '63'],
        }

    def gather_arguments(self):
        '''Populate the list of values for macro arguments.
Call this after parsing all the inputs.'''
        self.arguments_for['hash_alg'] = sorted(self.hash_algorithms)
        self.arguments_for['mac_alg'] = sorted(self.mac_algorithms)
        self.arguments_for['kdf_alg'] = sorted(self.kdf_algorithms)
        self.arguments_for['aead_alg'] = sorted(self.aead_algorithms)
        self.arguments_for['curve'] = sorted(self.ecc_curves)

    def format_arguments(self, name, arguments):
        '''Format a macro call with arguments..'''
        return name + '(' + ', '.join(arguments) + ')'

    def distribute_arguments(self, name):
        '''Generate macro calls with each tested argument set.
If name is a macro without arguments, just yield "name".
If name is a macro with arguments, yield a series of "name(arg1,...,argN)"
where each argument takes each possible value at least once.'''
        try:
            if name not in self.argspecs:
                yield name
                return
            argspec = self.argspecs[name]
            if argspec == []:
                yield name + '()'
                return
            argument_lists = [self.arguments_for[arg] for arg in argspec]
            arguments = [values[0] for values in argument_lists]
            yield self.format_arguments(name, arguments)
            for i in range(len(arguments)):
                for value in argument_lists[i][1:]:
                    arguments[i] = value
                    yield self.format_arguments(name, arguments)
                arguments[i] = argument_lists[0][0]
        except BaseException as e:
            raise Exception('distribute_arguments({})'.format(name)) from e

    # Regex for interesting header lines.
    # Groups: 1=macro name, 2=type, 3=argument list (optional).
    header_line_re = \
        re.compile(r'#define +' +
                   r'(PSA_((?:KEY_)?[A-Z]+)_\w+)' +
                   r'(?:\(([^\n()]*)\))?')
    # Regex of macro names to exclude.
    excluded_name_re = re.compile('_(?:GET|IS|OF)_|_(?:BASE|FLAG|MASK)\Z')
    # Additional excluded macros.
    # PSA_ALG_ECDH and PSA_ALG_FFDH are excluded for now as the script
    # currently doesn't support them. Deprecated errors are also excluded.
    excluded_names = set(['PSA_ALG_AEAD_WITH_DEFAULT_TAG_LENGTH',
                          'PSA_ALG_FULL_LENGTH_MAC',
                          'PSA_ALG_ECDH',
                          'PSA_ALG_FFDH',
                          'PSA_ERROR_UNKNOWN_ERROR',
                          'PSA_ERROR_OCCUPIED_SLOT',
                          'PSA_ERROR_EMPTY_SLOT',
                          'PSA_ERROR_INSUFFICIENT_CAPACITY',
                          ])
    argument_split_re = re.compile(r' *, *')
    def parse_header_line(self, line):
        '''Parse a C header line, looking for "#define PSA_xxx".'''
        m = re.match(self.header_line_re, line)
        if not m:
            return
        name = m.group(1)
        if re.search(self.excluded_name_re, name) or \
           name in self.excluded_names:
            return
        dest = self.table_by_prefix.get(m.group(2))
        if dest is None:
            return
        dest.add(name)
        if m.group(3):
            self.argspecs[name] = re.split(self.argument_split_re, m.group(3))

    def parse_header(self, filename):
        '''Parse a C header file, looking for "#define PSA_xxx".'''
        with read_file_lines(filename) as lines:
            for line in lines:
                self.parse_header_line(line)

    def add_test_case_line(self, function, argument):
        '''Parse a test case data line, looking for algorithm metadata tests.'''
        if function.endswith('_algorithm'):
            # As above, ECDH and FFDH algorithms are excluded for now.
            # Support for them will be added in the future.
            if 'ECDH' in argument or 'FFDH' in argument:
                return
            self.algorithms.add(argument)
            if function == 'hash_algorithm':
                self.hash_algorithms.add(argument)
            elif function in ['mac_algorithm', 'hmac_algorithm']:
                self.mac_algorithms.add(argument)
            elif function == 'aead_algorithm':
                self.aead_algorithms.add(argument)
        elif function == 'key_type':
            self.key_types.add(argument)
        elif function == 'ecc_key_types':
            self.ecc_curves.add(argument)

    # Regex matching a *.data line containing a test function call and
    # its arguments. The actual definition is partly positional, but this
    # regex is good enough in practice.
    test_case_line_re = re.compile('(?!depends_on:)(\w+):([^\n :][^:\n]*)')
    def parse_test_cases(self, filename):
        '''Parse a test case file (*.data), looking for algorithm metadata tests.'''
        with read_file_lines(filename) as lines:
            for line in lines:
                m = re.match(self.test_case_line_re, line)
                if m:
                    self.add_test_case_line(m.group(1), m.group(2))

def gather_inputs(headers, test_suites):
    '''Read the list of inputs to test psa_constant_names with.'''
    inputs = Inputs()
    for header in headers:
        inputs.parse_header(header)
    for test_cases in test_suites:
        inputs.parse_test_cases(test_cases)
    inputs.gather_arguments()
    return inputs

def remove_file_if_exists(filename):
    '''Remove the specified file, ignoring errors.'''
    if not filename:
        return
    try:
        os.remove(filename)
    except:
        pass

def run_c(options, type, names):
    '''Generate and run a program to print out numerical values for names.'''
    if type == 'status':
        cast_to = 'long'
        printf_format = '%ld'
    else:
        cast_to = 'unsigned long'
        printf_format = '0x%08lx'
    c_name = None
    exe_name = None
    try:
        c_fd, c_name = tempfile.mkstemp(prefix='tmp-{}-'.format(type),
                                        suffix='.c',
                                        dir='programs/psa')
        exe_suffix = '.exe' if platform.system() == 'Windows' else ''
        exe_name = c_name[:-2] + exe_suffix
        remove_file_if_exists(exe_name)
        c_file = os.fdopen(c_fd, 'w', encoding='ascii')
        c_file.write('/* Generated by test_psa_constant_names.py for {} values */'
                     .format(type))
        c_file.write('''
#include <stdio.h>
#include <psa/crypto.h>
int main(void)
{
''')
        for name in names:
            c_file.write('    printf("{}\\n", ({}) {});\n'
                         .format(printf_format, cast_to, name))
        c_file.write('''    return 0;
}
''')
        c_file.close()
        cc = os.getenv('CC', 'cc')
        subprocess.check_call([cc] +
                              ['-I' + dir for dir in options.include] +
                              ['-o', exe_name, c_name])
        if options.keep_c:
            sys.stderr.write('List of {} tests kept at {}\n'
                             .format(type, c_name))
        else:
            os.remove(c_name)
        output = subprocess.check_output([exe_name])
        return output.decode('ascii').strip().split('\n')
    finally:
        remove_file_if_exists(exe_name)

normalize_strip_re = re.compile(r'\s+')
def normalize(expr):
    '''Normalize the C expression so as not to care about trivial differences.
Currently "trivial differences" means whitespace.'''
    expr = re.sub(normalize_strip_re, '', expr, len(expr))
    return expr.strip().split('\n')

def do_test(options, inputs, type, names):
    '''Test psa_constant_names for the specified type.
Run program on names.
Use inputs to figure out what arguments to pass to macros that take arguments.'''
    names = sorted(itertools.chain(*map(inputs.distribute_arguments, names)))
    values = run_c(options, type, names)
    output = subprocess.check_output([options.program, type] + values)
    outputs = output.decode('ascii').strip().split('\n')
    errors = [(type, name, value, output)
              for (name, value, output) in zip(names, values, outputs)
              if normalize(name) != normalize(output)]
    return len(names), errors

def report_errors(errors):
    '''Describe each case where the output is not as expected.'''
    for type, name, value, output in errors:
        print('For {} "{}", got "{}" (value: {})'
              .format(type, name, output, value))

def run_tests(options, inputs):
    '''Run psa_constant_names on all the gathered inputs.
Return a tuple (count, errors) where count is the total number of inputs
that were tested and errors is the list of cases where the output was
not as expected.'''
    count = 0
    errors = []
    for type, names in [('status', inputs.statuses),
                        ('algorithm', inputs.algorithms),
                        ('ecc_curve', inputs.ecc_curves),
                        ('key_type', inputs.key_types),
                        ('key_usage', inputs.key_usage_flags)]:
        c, e = do_test(options, inputs, type, names)
        count += c
        errors += e
    return count, errors

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=globals()['__doc__'])
    parser.add_argument('--include', '-I',
                        action='append', default=['include'],
                        help='Directory for header files')
    parser.add_argument('--program',
                        default='programs/psa/psa_constant_names',
                        help='Program to test')
    parser.add_argument('--keep-c',
                        action='store_true', dest='keep_c', default=False,
                        help='Keep the intermediate C file')
    parser.add_argument('--no-keep-c',
                        action='store_false', dest='keep_c',
                        help='Don\'t keep the intermediate C file (default)')
    options = parser.parse_args()
    headers = [os.path.join(options.include[0], 'psa', h)
               for h in ['crypto.h', 'crypto_extra.h', 'crypto_values.h']]
    test_suites = ['tests/suites/test_suite_psa_crypto_metadata.data']
    inputs = gather_inputs(headers, test_suites)
    count, errors = run_tests(options, inputs)
    report_errors(errors)
    if errors == []:
        print('{} test cases PASS'.format(count))
    else:
        print('{} test cases, {} FAIL'.format(count, len(errors)))
        exit(1)
