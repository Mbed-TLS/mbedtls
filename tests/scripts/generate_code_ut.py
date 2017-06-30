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
from StringIO import StringIO
from unittest import TestCase, main as unittest_main
from mock import patch
from generate_code import *


"""
Unit tests for generate_code.py
"""


class GenDep(TestCase):
    """
    Test suite for function gen_dep()
    """

    def test_deps_list(self):
        """
        Test that gen_dep() correctly creates deps for given dependency list.
        :return: 
        """
        deps = ['DEP1', 'DEP2']
        dep_start, dep_end = gen_deps(deps)
        ifdef1, ifdef2 = dep_start.splitlines()
        endif1, endif2 = dep_end.splitlines()
        self.assertEqual(ifdef1, '#if defined(DEP1)', 'ifdef generated incorrectly')
        self.assertEqual(ifdef2, '#if defined(DEP2)', 'ifdef generated incorrectly')
        self.assertEqual(endif1, '#endif /* DEP2 */', 'endif generated incorrectly')
        self.assertEqual(endif2, '#endif /* DEP1 */', 'endif generated incorrectly')

    def test_disabled_deps_list(self):
        """
        Test that gen_dep() correctly creates deps for given dependency list.
        :return: 
        """
        deps = ['!DEP1', '!DEP2']
        dep_start, dep_end = gen_deps(deps)
        ifdef1, ifdef2 = dep_start.splitlines()
        endif1, endif2 = dep_end.splitlines()
        self.assertEqual(ifdef1, '#if !defined(DEP1)', 'ifdef generated incorrectly')
        self.assertEqual(ifdef2, '#if !defined(DEP2)', 'ifdef generated incorrectly')
        self.assertEqual(endif1, '#endif /* !DEP2 */', 'endif generated incorrectly')
        self.assertEqual(endif2, '#endif /* !DEP1 */', 'endif generated incorrectly')

    def test_mixed_deps_list(self):
        """
        Test that gen_dep() correctly creates deps for given dependency list.
        :return: 
        """
        deps = ['!DEP1', 'DEP2']
        dep_start, dep_end = gen_deps(deps)
        ifdef1, ifdef2 = dep_start.splitlines()
        endif1, endif2 = dep_end.splitlines()
        self.assertEqual(ifdef1, '#if !defined(DEP1)', 'ifdef generated incorrectly')
        self.assertEqual(ifdef2, '#if defined(DEP2)', 'ifdef generated incorrectly')
        self.assertEqual(endif1, '#endif /* DEP2 */', 'endif generated incorrectly')
        self.assertEqual(endif2, '#endif /* !DEP1 */', 'endif generated incorrectly')

    def test_empty_deps_list(self):
        """
        Test that gen_dep() correctly creates deps for given dependency list.
        :return: 
        """
        deps = []
        dep_start, dep_end = gen_deps(deps)
        self.assertEqual(dep_start, '', 'ifdef generated incorrectly')
        self.assertEqual(dep_end, '', 'ifdef generated incorrectly')

    def test_large_deps_list(self):
        """
        Test that gen_dep() correctly creates deps for given dependency list.
        :return: 
        """
        deps = []
        count = 10
        for i in range(count):
            deps.append('DEP%d' % i)
        dep_start, dep_end = gen_deps(deps)
        self.assertEqual(len(dep_start.splitlines()), count, 'ifdef generated incorrectly')
        self.assertEqual(len(dep_end.splitlines()), count, 'ifdef generated incorrectly')


class GenDepOneLine(TestCase):
    """
    Test Suite for testing gen_deps_one_line()
    """

    def test_deps_list(self):
        """
        Test that gen_dep() correctly creates deps for given dependency list.
        :return: 
        """
        deps = ['DEP1', 'DEP2']
        dep_str = gen_deps_one_line(deps)
        self.assertEqual(dep_str, '#if defined(DEP1) && defined(DEP2)', 'ifdef generated incorrectly')

    def test_disabled_deps_list(self):
        """
        Test that gen_dep() correctly creates deps for given dependency list.
        :return:
        """
        deps = ['!DEP1', '!DEP2']
        dep_str = gen_deps_one_line(deps)
        self.assertEqual(dep_str, '#if !defined(DEP1) && !defined(DEP2)', 'ifdef generated incorrectly')

    def test_mixed_deps_list(self):
        """
        Test that gen_dep() correctly creates deps for given dependency list.
        :return:
        """
        deps = ['!DEP1', 'DEP2']
        dep_str = gen_deps_one_line(deps)
        self.assertEqual(dep_str, '#if !defined(DEP1) && defined(DEP2)', 'ifdef generated incorrectly')

    def test_empty_deps_list(self):
        """
        Test that gen_dep() correctly creates deps for given dependency list.
        :return:
        """
        deps = []
        dep_str = gen_deps_one_line(deps)
        self.assertEqual(dep_str, '', 'ifdef generated incorrectly')

    def test_large_deps_list(self):
        """
        Test that gen_dep() correctly creates deps for given dependency list.
        :return:
        """
        deps = []
        count = 10
        for i in range(count):
            deps.append('DEP%d' % i)
        dep_str = gen_deps_one_line(deps)
        expected = '#if ' + ' && '.join(['defined(%s)' % x for x in deps])
        self.assertEqual(dep_str, expected, 'ifdef generated incorrectly')


class GenFunctionWrapper(TestCase):
    """
    Test Suite for testing gen_function_wrapper()
    """

    def test_params_unpack(self):
        """
        Test that params are properly unpacked in the function call.
        
        :return: 
        """
        code = gen_function_wrapper('test_a', '', ('a', 'b', 'c', 'd'))
        expected = '''
void test_a_wrapper( void ** params )
{
    

    test_a( a, b, c, d );
}
'''
        self.assertEqual(code, expected)

    def test_local(self):
        """
        Test that params are properly unpacked in the function call.
        
        :return: 
        """
        code = gen_function_wrapper('test_a', 'int x = 1;', ('x', 'b', 'c', 'd'))
        expected = '''
void test_a_wrapper( void ** params )
{
    
int x = 1;
    test_a( x, b, c, d );
}
'''
        self.assertEqual(code, expected)

    def test_empty_params(self):
        """
        Test that params are properly unpacked in the function call.
        
        :return: 
        """
        code = gen_function_wrapper('test_a', '', ())
        expected = '''
void test_a_wrapper( void ** params )
{
    (void)params;

    test_a(  );
}
'''
        self.assertEqual(code, expected)


class GenDispatch(TestCase):
    """
    Test suite for testing gen_dispatch()
    """

    def test_dispatch(self):
        """
        Test that dispatch table entry is generated correctly.
        :return: 
        """
        code = gen_dispatch('test_a', ['DEP1', 'DEP2'])
        expected = '''
#if defined(DEP1) && defined(DEP2)
    test_a_wrapper,
#else
    NULL,
#endif
'''
        self.assertEqual(code, expected)

    def test_empty_deps(self):
        """
        Test empty dependency list.
        :return: 
        """
        code = gen_dispatch('test_a', [])
        expected = '''
    test_a_wrapper,
'''
        self.assertEqual(code, expected)


class StringIOWrapper(StringIO, object):
    """
    file like class to mock file object in tests.
    """
    def __init__(self, file_name, data, line_no = 1):
        """
        Init file handle.
        
        :param file_name: 
        :param data:
        :param line_no:
        """
        super(StringIOWrapper, self).__init__(data)
        self.line_no = line_no
        self.name = file_name

    def next(self):
        """
        Iterator return impl.
        :return: 
        """
        line = super(StringIOWrapper, self).next()
        return line

    def readline(self, limit=0):
        """
        Wrap the base class readline.
        
        :param limit: 
        :return: 
        """
        line = super(StringIOWrapper, self).readline()
        if line:
            self.line_no += 1
        return line


class ParseSuiteHeaders(TestCase):
    """
    Test Suite for testing parse_suite_headers().
    """

    def test_suite_headers(self):
        """
        Test that suite headers are parsed correctly.
        
        :return: 
        """
        data = '''#include "mbedtls/ecp.h"

#define ECP_PF_UNKNOWN     -1
/* END_HEADER */
'''
        expected = '''#line 1 "test_suite_ut.function"
#include "mbedtls/ecp.h"

#define ECP_PF_UNKNOWN     -1
'''
        s = StringIOWrapper('test_suite_ut.function', data, line_no=0)
        headers = parse_suite_headers(s)
        self.assertEqual(headers, expected)

    def test_line_no(self):
        """
        Test that #line is set to correct line no. in source .function file. 
        
        :return: 
        """
        data = '''#include "mbedtls/ecp.h"

#define ECP_PF_UNKNOWN     -1
/* END_HEADER */
'''
        offset_line_no = 5
        expected = '''#line %d "test_suite_ut.function"
#include "mbedtls/ecp.h"

#define ECP_PF_UNKNOWN     -1
''' % (offset_line_no + 1)
        s = StringIOWrapper('test_suite_ut.function', data, offset_line_no)
        headers = parse_suite_headers(s)
        self.assertEqual(headers, expected)

    def test_no_end_header_comment(self):
        """
        Test that InvalidFileFormat is raised when end header comment is missing.
        :return: 
        """
        data = '''#include "mbedtls/ecp.h"

#define ECP_PF_UNKNOWN     -1

'''
        s = StringIOWrapper('test_suite_ut.function', data)
        self.assertRaises(InvalidFileFormat, parse_suite_headers, s)


class ParseSuiteDeps(TestCase):
    """
    Test Suite for testing parse_suite_deps().
    """

    def test_suite_deps(self):
        """
        
        :return: 
        """
        data = '''
 * depends_on:MBEDTLS_ECP_C
 * END_DEPENDENCIES
 */
'''
        expected = ['MBEDTLS_ECP_C']
        s = StringIOWrapper('test_suite_ut.function', data)
        deps = parse_suite_deps(s)
        self.assertEqual(deps, expected)

    def test_no_end_dep_comment(self):
        """
        Test that InvalidFileFormat is raised when end dep comment is missing.
        :return: 
        """
        data = '''
* depends_on:MBEDTLS_ECP_C
'''
        s = StringIOWrapper('test_suite_ut.function', data)
        self.assertRaises(InvalidFileFormat, parse_suite_deps, s)

    def test_deps_split(self):
        """
        Test that InvalidFileFormat is raised when end dep comment is missing.
        :return: 
        """
        data = '''
 * depends_on:MBEDTLS_ECP_C:A:B:   C  : D :F : G: !H 
 * END_DEPENDENCIES
 */
'''
        expected = ['MBEDTLS_ECP_C', 'A', 'B', 'C', 'D', 'F', 'G', '!H']
        s = StringIOWrapper('test_suite_ut.function', data)
        deps = parse_suite_deps(s)
        self.assertEqual(deps, expected)


class ParseFuncDeps(TestCase):
    """
    Test Suite for testing parse_function_deps() 
    """

    def test_function_deps(self):
        """
        Test that parse_function_deps() correctly parses function dependencies.
        :return: 
        """
        line = '/* BEGIN_CASE depends_on:MBEDTLS_ENTROPY_NV_SEED:MBEDTLS_FS_IO */'
        expected = ['MBEDTLS_ENTROPY_NV_SEED', 'MBEDTLS_FS_IO']
        deps = parse_function_deps(line)
        self.assertEqual(deps, expected)

    def test_no_deps(self):
        """
        Test that parse_function_deps() correctly parses function dependencies.
        :return: 
        """
        line = '/* BEGIN_CASE */'
        deps = parse_function_deps(line)
        self.assertEqual(deps, [])

    def test_poorly_defined_deps(self):
        """
        Test that parse_function_deps() correctly parses function dependencies.
        :return: 
        """
        line = '/* BEGIN_CASE depends_on:MBEDTLS_FS_IO: A : !B:C : F*/'
        deps = parse_function_deps(line)
        self.assertEqual(deps, ['MBEDTLS_FS_IO', 'A', '!B', 'C', 'F'])


class ParseFuncSignature(TestCase):
    """
    Test Suite for parse_function_signature(). 
    """

    def test_int_and_char_params(self):
        """
        
        :return: 
        """
        line = 'void entropy_threshold( char * a, int b, int result )'
        name, args, local, arg_dispatch = parse_function_signature(line)
        self.assertEqual(name, 'entropy_threshold')
        self.assertEqual(args, ['char*', 'int', 'int'])
        self.assertEqual(local, '')
        self.assertEqual(arg_dispatch, ['(char *) params[0]', '*( (int *) params[1] )', '*( (int *) params[2] )'])

    def test_hex_params(self):
        """
        
        :return: 
        """
        line = 'void entropy_threshold( char * a, HexParam_t * h, int result )'
        name, args, local, arg_dispatch = parse_function_signature(line)
        self.assertEqual(name, 'entropy_threshold')
        self.assertEqual(args, ['char*', 'hex', 'int'])
        self.assertEqual(local, '    HexParam_t hex1 = {(uint8_t *) params[1], *( (uint32_t *) params[2] )};\n')
        self.assertEqual(arg_dispatch, ['(char *) params[0]', '&hex1', '*( (int *) params[3] )'])

    def test_non_void_function(self):
        """
        
        :return: 
        """
        line = 'int entropy_threshold( char * a, HexParam_t * h, int result )'
        self.assertRaises(ValueError, parse_function_signature, line)

    def test_unsupported_arg(self):
        """
        
        :return: 
        """
        line = 'int entropy_threshold( char * a, HexParam_t * h, int * result )'
        self.assertRaises(ValueError, parse_function_signature, line)

    def test_no_params(self):
        """
        
        :return: 
        """
        line = 'void entropy_threshold()'
        name, args, local, arg_dispatch = parse_function_signature(line)
        self.assertEqual(name, 'entropy_threshold')
        self.assertEqual(args, [])
        self.assertEqual(local, '')
        self.assertEqual(arg_dispatch, [])


class ParseFunctionCode(TestCase):
    """
    Test suite for testing parse_function_code()
    """

    def test_no_function(self):
        """
        
        :return: 
        """
        data = '''
No
test
function
'''
        s = StringIOWrapper('test_suite_ut.function', data)
        self.assertRaises(InvalidFileFormat, parse_function_code, s, [], [])

    def test_no_end_case_comment(self):
        """
        
        :return: 
        """
        data = '''
void test_func()
{
}
'''
        s = StringIOWrapper('test_suite_ut.function', data)
        self.assertRaises(InvalidFileFormat, parse_function_code, s, [], [])

    @patch("generate_code.parse_function_signature")
    def test_parse_function_signature_called(self, parse_function_signature_mock):
        """
        
        :return: 
        """
        parse_function_signature_mock.return_value = ('test_func', [], '', [])
        data = '''
void test_func()
{
}
'''
        s = StringIOWrapper('test_suite_ut.function', data)
        self.assertRaises(InvalidFileFormat, parse_function_code, s, [], [])
        self.assertTrue(parse_function_signature_mock.called)
        parse_function_signature_mock.assert_called_with('void test_func()\n')

    @patch("generate_code.gen_dispatch")
    @patch("generate_code.gen_deps")
    @patch("generate_code.gen_function_wrapper")
    @patch("generate_code.parse_function_signature")
    def test_return(self, parse_function_signature_mock,
                                             gen_function_wrapper_mock,
                                             gen_deps_mock,
                                             gen_dispatch_mock):
        """
        
        :return: 
        """
        parse_function_signature_mock.return_value = ('func', [], '', [])
        gen_function_wrapper_mock.return_value = ''
        gen_deps_mock.side_effect = gen_deps
        gen_dispatch_mock.side_effect = gen_dispatch
        data = '''
void func()
{
    ba ba black sheep
    have you any wool
}
/* END_CASE */
'''
        s = StringIOWrapper('test_suite_ut.function', data)
        name, arg, code, dispatch_code = parse_function_code(s, [], [])

        #self.assertRaises(InvalidFileFormat, parse_function_code, s, [], [])
        self.assertTrue(parse_function_signature_mock.called)
        parse_function_signature_mock.assert_called_with('void func()\n')
        gen_function_wrapper_mock.assert_called_with('test_func', '', [])
        self.assertEqual(name, 'test_func')
        self.assertEqual(arg, [])
        expected = '''#line 2 "test_suite_ut.function"
void test_func()
{
    ba ba black sheep
    have you any wool
exit:
    ;;
}
'''
        self.assertEqual(code, expected)
        self.assertEqual(dispatch_code, "\n    test_func_wrapper,\n")

    @patch("generate_code.gen_dispatch")
    @patch("generate_code.gen_deps")
    @patch("generate_code.gen_function_wrapper")
    @patch("generate_code.parse_function_signature")
    def test_with_exit_label(self, parse_function_signature_mock,
                           gen_function_wrapper_mock,
                           gen_deps_mock,
                           gen_dispatch_mock):
        """
        
        :return: 
        """
        parse_function_signature_mock.return_value = ('func', [], '', [])
        gen_function_wrapper_mock.return_value = ''
        gen_deps_mock.side_effect = gen_deps
        gen_dispatch_mock.side_effect = gen_dispatch
        data = '''
void func()
{
    ba ba black sheep
    have you any wool
exit:
    yes sir yes sir
    3 bags full
}
/* END_CASE */
'''
        s = StringIOWrapper('test_suite_ut.function', data)
        name, arg, code, dispatch_code = parse_function_code(s, [], [])

        expected = '''#line 2 "test_suite_ut.function"
void test_func()
{
    ba ba black sheep
    have you any wool
exit:
    yes sir yes sir
    3 bags full
}
'''
        self.assertEqual(code, expected)


class ParseFunction(TestCase):
    """
    Test Suite for testing parse_functions()
    """

    @patch("generate_code.parse_suite_headers")
    def test_begin_header(self, parse_suite_headers_mock):
        """
        Test that begin header is checked and parse_suite_headers() is called.
        :return: 
        """
        def stop(this):
            raise Exception
        parse_suite_headers_mock.side_effect = stop
        data = '''/* BEGIN_HEADER */
#include "mbedtls/ecp.h"

#define ECP_PF_UNKNOWN     -1
/* END_HEADER */
'''
        s = StringIOWrapper('test_suite_ut.function', data)
        self.assertRaises(Exception, parse_functions, s)
        parse_suite_headers_mock.assert_called_with(s)
        self.assertEqual(s.line_no, 2)

    @patch("generate_code.parse_suite_deps")
    def test_begin_dep(self, parse_suite_deps_mock):
        """
        Test that begin header is checked and parse_suite_headers() is called.
        :return: 
        """
        def stop(this):
            raise Exception
        parse_suite_deps_mock.side_effect = stop
        data = '''/* BEGIN_DEPENDENCIES
 * depends_on:MBEDTLS_ECP_C
 * END_DEPENDENCIES
 */
'''
        s = StringIOWrapper('test_suite_ut.function', data)
        self.assertRaises(Exception, parse_functions, s)
        parse_suite_deps_mock.assert_called_with(s)
        self.assertEqual(s.line_no, 2)

    @patch("generate_code.parse_function_deps")
    def test_begin_function_dep(self, parse_function_deps_mock):
        """
        Test that begin header is checked and parse_suite_headers() is called.
        :return: 
        """
        def stop(this):
            raise Exception
        parse_function_deps_mock.side_effect = stop

        deps_str = '/* BEGIN_CASE depends_on:MBEDTLS_ENTROPY_NV_SEED:MBEDTLS_FS_IO */\n'
        data = '''%svoid test_func()
{
}
''' % deps_str
        s = StringIOWrapper('test_suite_ut.function', data)
        self.assertRaises(Exception, parse_functions, s)
        parse_function_deps_mock.assert_called_with(deps_str)
        self.assertEqual(s.line_no, 2)

    @patch("generate_code.parse_function_code")
    @patch("generate_code.parse_function_deps")
    def test_return(self, parse_function_deps_mock, parse_function_code_mock):
        """
        Test that begin header is checked and parse_suite_headers() is called.
        :return: 
        """
        def stop(this):
            raise Exception
        parse_function_deps_mock.return_value = []
        in_func_code= '''void test_func()
{
}
'''
        func_dispatch = '''
    test_func_wrapper,
'''
        parse_function_code_mock.return_value = 'test_func', [], in_func_code, func_dispatch
        deps_str = '/* BEGIN_CASE depends_on:MBEDTLS_ENTROPY_NV_SEED:MBEDTLS_FS_IO */\n'
        data = '''%svoid test_func()
{
}
''' % deps_str
        s = StringIOWrapper('test_suite_ut.function', data)
        suite_deps, dispatch_code, func_code, func_info = parse_functions(s)
        parse_function_deps_mock.assert_called_with(deps_str)
        parse_function_code_mock.assert_called_with(s, [], [])
        self.assertEqual(s.line_no, 5)
        self.assertEqual(suite_deps, [])
        expected_dispatch_code = '''/* Function Id: 0 */

    test_func_wrapper,
'''
        self.assertEqual(dispatch_code, expected_dispatch_code)
        self.assertEqual(func_code, in_func_code)
        self.assertEqual(func_info, {'test_func': (0, [])})

    def test_parsing(self):
        """
        Test that begin header is checked and parse_suite_headers() is called.
        :return: 
        """
        data = '''/* BEGIN_HEADER */
#include "mbedtls/ecp.h"

#define ECP_PF_UNKNOWN     -1
/* END_HEADER */

/* BEGIN_DEPENDENCIES
 * depends_on:MBEDTLS_ECP_C
 * END_DEPENDENCIES
 */

/* BEGIN_CASE depends_on:MBEDTLS_ENTROPY_NV_SEED:MBEDTLS_FS_IO */
void func1()
{
}
/* END_CASE */

/* BEGIN_CASE depends_on:MBEDTLS_ENTROPY_NV_SEED:MBEDTLS_FS_IO */
void func2()
{
}
/* END_CASE */
'''
        s = StringIOWrapper('test_suite_ut.function', data)
        suite_deps, dispatch_code, func_code, func_info = parse_functions(s)
        self.assertEqual(s.line_no, 23)
        self.assertEqual(suite_deps, ['MBEDTLS_ECP_C'])

        expected_dispatch_code = '''/* Function Id: 0 */

#if defined(MBEDTLS_ECP_C) && defined(MBEDTLS_ENTROPY_NV_SEED) && defined(MBEDTLS_FS_IO)
    test_func1_wrapper,
#else
    NULL,
#endif
/* Function Id: 1 */

#if defined(MBEDTLS_ECP_C) && defined(MBEDTLS_ENTROPY_NV_SEED) && defined(MBEDTLS_FS_IO)
    test_func2_wrapper,
#else
    NULL,
#endif
'''
        self.assertEqual(dispatch_code, expected_dispatch_code)
        expected_func_code = '''#if defined(MBEDTLS_ECP_C)
#line 3 "test_suite_ut.function"
#include "mbedtls/ecp.h"

#define ECP_PF_UNKNOWN     -1
#if defined(MBEDTLS_ENTROPY_NV_SEED)
#if defined(MBEDTLS_FS_IO)
#line 14 "test_suite_ut.function"
void test_func1()
{
exit:
    ;;
}

void test_func1_wrapper( void ** params )
{
    (void)params;

    test_func1(  );
}
#endif /* MBEDTLS_FS_IO */
#endif /* MBEDTLS_ENTROPY_NV_SEED */
#if defined(MBEDTLS_ENTROPY_NV_SEED)
#if defined(MBEDTLS_FS_IO)
#line 20 "test_suite_ut.function"
void test_func2()
{
exit:
    ;;
}

void test_func2_wrapper( void ** params )
{
    (void)params;

    test_func2(  );
}
#endif /* MBEDTLS_FS_IO */
#endif /* MBEDTLS_ENTROPY_NV_SEED */
#endif /* MBEDTLS_ECP_C */
'''
        self.assertEqual(func_code, expected_func_code)
        self.assertEqual(func_info, {'test_func1': (0, []), 'test_func2': (1, [])})

    def test_same_function_name(self):
        """
        Test that begin header is checked and parse_suite_headers() is called.
        :return: 
        """
        data = '''/* BEGIN_HEADER */
#include "mbedtls/ecp.h"

#define ECP_PF_UNKNOWN     -1
/* END_HEADER */

/* BEGIN_DEPENDENCIES
 * depends_on:MBEDTLS_ECP_C
 * END_DEPENDENCIES
 */

/* BEGIN_CASE depends_on:MBEDTLS_ENTROPY_NV_SEED:MBEDTLS_FS_IO */
void func()
{
}
/* END_CASE */

/* BEGIN_CASE depends_on:MBEDTLS_ENTROPY_NV_SEED:MBEDTLS_FS_IO */
void func()
{
}
/* END_CASE */
'''
        s = StringIOWrapper('test_suite_ut.function', data)
        self.assertRaises(AssertionError, parse_functions, s)


if __name__=='__main__':
    unittest_main()