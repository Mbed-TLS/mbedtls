# Greentea host test script for on-target tests.
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
Greentea host test script for on-target tests.

Host test script for testing mbed TLS test suites on target. Implements
BaseHostTest to handle key,value pairs (events) coming from mbed TLS
tests. Reads data file corresponding to the executing binary and dispatches
test cases.
"""


import re
import os
import binascii
from mbed_host_tests import BaseHostTest, event_callback


class TestDataParser(object):
    """
    parser for mbedtls test data files.
    """

    def __init__(self):
        """
        Constructor
        """
        self.tests = []

    def parse(self, data_file):
        """
        Data file parser.

        :param data_file: Data file path
        """
        with open(data_file, 'r') as f:
            self.__parse(f)

    @staticmethod
    def __escaped_split(str, ch):
        """
        Splits str on ch except when escaped.

        :param str: String to split
        :param ch: Split character
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

    def __parse(self, file):
        """
        Parses data file using supplied file object.

        :param file: Data file object
        :return:
        """
        for line in file:
            line = line.strip()
            if len(line) == 0:
                continue
            # Read test name
            name = line

            # Check dependencies
            deps = []
            line = file.next().strip()
            m = re.search('depends_on\:(.*)', line)
            if m:
                deps = [int(x) for x in m.group(1).split(':')]
                line = file.next().strip()

            # Read test vectors
            line = line.replace('\\n', '\n')
            parts = self.__escaped_split(line, ':')
            function = int(parts[0])
            x = parts[1:]
            l = len(x)
            assert l % 2 == 0, "Number of test arguments should be even: %s" % line
            args = [(x[i * 2], x[(i * 2) + 1]) for i in range(len(x)/2)]
            self.tests.append((name, function, deps, args))

    def get_test_data(self):
        """
        Returns test data.
        """
        return self.tests


class MbedTlsTest(BaseHostTest):
    """
    Event handler for mbedtls unit tests. This script is loaded at run time
    by htrun while executing mbedtls unit tests.
    """
    # From suites/helpers.function
    DEPENDENCY_SUPPORTED = 0
    KEY_VALUE_MAPPING_FOUND = DEPENDENCY_SUPPORTED
    DISPATCH_TEST_SUCCESS = DEPENDENCY_SUPPORTED

    KEY_VALUE_MAPPING_NOT_FOUND = -1
    DEPENDENCY_NOT_SUPPORTED = -2
    DISPATCH_TEST_FN_NOT_FOUND = -3
    DISPATCH_INVALID_TEST_DATA = -4
    DISPATCH_UNSUPPORTED_SUITE = -5

    def __init__(self):
        """
        Constructor initialises test index to 0.
        """
        super(MbedTlsTest, self).__init__()
        self.tests = []
        self.test_index = -1
        self.dep_index = 0
        self.error_str = dict()
        self.error_str[self.DEPENDENCY_SUPPORTED] = 'DEPENDENCY_SUPPORTED'
        self.error_str[self.KEY_VALUE_MAPPING_NOT_FOUND] = 'KEY_VALUE_MAPPING_NOT_FOUND'
        self.error_str[self.DEPENDENCY_NOT_SUPPORTED] = 'DEPENDENCY_NOT_SUPPORTED'
        self.error_str[self.DISPATCH_TEST_FN_NOT_FOUND] = 'DISPATCH_TEST_FN_NOT_FOUND'
        self.error_str[self.DISPATCH_INVALID_TEST_DATA] = 'DISPATCH_INVALID_TEST_DATA'
        self.error_str[self.DISPATCH_UNSUPPORTED_SUITE] = 'DISPATCH_UNSUPPORTED_SUITE'

    def setup(self):
        """
        Setup hook implementation. Reads test suite data file and parses out tests.
        """
        binary_path = self.get_config_item('image_path')
        script_dir = os.path.split(os.path.abspath(__file__))[0]
        suite_name = os.path.splitext(os.path.basename(binary_path))[0]
        data_file = ".".join((suite_name, 'data'))
        data_file = os.path.join(script_dir, '..', 'mbedtls', suite_name, data_file)
        if os.path.exists(data_file):
            self.log("Running tests from %s" % data_file)
            parser = TestDataParser()
            parser.parse(data_file)
            self.tests = parser.get_test_data()
            self.print_test_info()
        else:
            self.log("Data file not found: %s" % data_file)
            self.notify_complete(False)

    def print_test_info(self):
        """
        Prints test summary read by Greentea to detect test cases.
        """
        self.log('{{__testcase_count;%d}}' % len(self.tests))
        for name, _, _, _ in self.tests:
            self.log('{{__testcase_name;%s}}' % name)

    @staticmethod
    def align_32bit(b):
        """
        4 byte aligns input byte array.

        :return:
        """
        b += bytearray((4 - (len(b))) % 4)

    @staticmethod
    def hex_str_bytes(hex_str):
        """
        Converts Hex string representation to byte array

        :param hex_str: Hex in string format.
        :return: Output Byte array
        """
        assert hex_str[0] == '"' and hex_str[len(hex_str) - 1] == '"', \
            "HEX test parameter missing '\"': %s" % hex_str
        hex_str = hex_str.strip('"')
        assert len(hex_str) % 2 == 0, "HEX parameter len should be mod of 2: %s" % hex_str

        b = binascii.unhexlify(hex_str)
        return b

    @staticmethod
    def int32_to_bigendian_bytes(i):
        """
        Coverts i to bytearray in big endian format.

        :param i: Input integer
        :return: Output bytes array in big endian or network order
        """
        b = bytearray([((i >> x) & 0xff) for x in [24, 16, 8, 0]])
        return b

    def test_vector_to_bytes(self, function_id, deps, parameters):
        """
        Converts test vector into a byte array that can be sent to the target.

        :param function_id: Test Function Identifier
        :param deps: Dependency list
        :param parameters: Test function input parameters
        :return: Byte array and its length
        """
        b = bytearray([len(deps)])
        if len(deps):
            b += bytearray(deps)
        b += bytearray([function_id, len(parameters)])
        for typ, param in parameters:
            if typ == 'int' or typ == 'exp':
                i = int(param)
                b += 'I' if typ == 'int' else 'E'
                self.align_32bit(b)
                b += self.int32_to_bigendian_bytes(i)
            elif typ == 'char*':
                param = param.strip('"')
                i = len(param) + 1  # + 1 for null termination
                b += 'S'
                self.align_32bit(b)
                b += self.int32_to_bigendian_bytes(i)
                b += bytearray(list(param))
                b += '\0'   # Null terminate
            elif typ == 'hex':
                hb = self.hex_str_bytes(param)
                b += 'H'
                self.align_32bit(b)
                i = len(hb)
                b += self.int32_to_bigendian_bytes(i)
                b += hb
        length = self.int32_to_bigendian_bytes(len(b))
        return b, length

    def run_next_test(self):
        """
        Send next test function to the target.

        """
        self.test_index += 1
        self.dep_index = 0
        if self.test_index < len(self.tests):
            name, function_id, deps, args = self.tests[self.test_index]
            self.run_test(name, function_id, deps, args)
        else:
            self.notify_complete(True)

    def run_test(self, name, function_id, deps, args):
        """
        Runs the test.

        :param name: Test name
        :param function_id: function identifier
        :param deps: Dependencies list
        :param args: test parameters
        :return:
        """
        self.log("Running: %s" % name)

        bytes, length = self.test_vector_to_bytes(function_id, deps, args)
        self.send_kv(length, bytes)

    @staticmethod
    def get_result(value):
        """
        Converts result from string type to integer
        :param value: Result code in string
        :return: Integer result code
        """
        try:
            return int(value)
        except ValueError:
            ValueError("Result should return error number. Instead received %s" % value)
        return 0

    @event_callback('GO')
    def on_go(self, key, value, timestamp):
        """
        Called on key "GO". Kicks off test execution.

        :param key: Event key
        :param value: Value. ignored
        :param timestamp: Timestamp ignored.
        :return:
        """
        self.run_next_test()

    @event_callback("R")
    def on_result(self, key, value, timestamp):
        """
        Handle result. Prints test start, finish prints required by Greentea to detect test execution.

        :param key: Event key
        :param value: Value. ignored
        :param timestamp: Timestamp ignored.
        :return:
        """
        int_val = self.get_result(value)
        name, function, deps, args = self.tests[self.test_index]
        self.log('{{__testcase_start;%s}}' % name)
        self.log('{{__testcase_finish;%s;%d;%d}}' % (name, int_val == 0,
                                                     int_val != 0))
        self.run_next_test()

    @event_callback("F")
    def on_failure(self, key, value, timestamp):
        """
        Handles test execution failure. That means dependency not supported or
        Test function not supported. Hence marking test as skipped.

        :param key: Event key
        :param value: Value. ignored
        :param timestamp: Timestamp ignored.
        :return:
        """
        int_val = self.get_result(value)
        name, function, deps, args = self.tests[self.test_index]
        if int_val in self.error_str:
            err = self.error_str[int_val]
        else:
            err = 'Unknown error'
        # For skip status, do not write {{__testcase_finish;...}}
        self.log("Error: %s" % err)
        self.run_next_test()
