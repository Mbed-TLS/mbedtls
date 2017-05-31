"""
mbed SDK
Copyright (c) 2011-2013 ARM Limited

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

import re
import os
import time
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

        """
        with open(data_file, 'r') as f:
            self.__parse(f)

    @staticmethod
    def __escaped_split(str, ch):
        """
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
        """
        line = file.readline().strip()
        while line:
            line = line.strip()
            if len(line) == 0:
                line = file.readline()
                continue
            # Read test name
            name = line

            # Check dependencies
            deps = []
            line = file.readline().strip()
            m = re.search('depends_on\:(.*)', line)
            if m:
                deps = [int(x) for x in m.group(1).split(':')]
                line = file.readline().strip()

            # Read test vectors
            line = line.replace('\\n', '\n#')
            parts = self.__escaped_split(line, ':')
            function = int(parts[0])
            x = parts[1:]
            l = len(x)
            assert l % 2 == 0, "Number of test arguments should be even: %s" % line
            args = [(x[i * 2], x[(i * 2) + 1]) for i in range(len(x)/2)]
            self.tests.append((name, function, deps, args))
            line = file.readline()

    def get_test_data(self):
        """
        """
        return self.tests


class MbedTlsTest(BaseHostTest):
    """
    Host test for mbed-tls target tests.
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
        """
        self.log('{{__testcase_count;%d}}' % len(self.tests))
        for name, _, _, _ in self.tests:
            self.log('{{__testcase_name;%s}}' % name)

    @staticmethod
    def align_32bit(b):
        """
        4 byte aligns byte array.

        :return:
        """
        b += bytearray((4 - (len(b))) % 4)

    def parameters_to_bytes(self, b, parameters):
        for typ, param in parameters:
            if typ == 'int' or typ == 'exp':
                i = int(param)
                b += 'I' if typ == 'int' else 'E'
                self.align_32bit(b)
                b += bytearray([((i >> x) & 0xff) for x in [24, 16, 8, 0]])
            elif typ == 'char*':
                param = param.strip('"')
                i = len(param) + 1  # + 1 for null termination
                b += 'S'
                self.align_32bit(b)
                b += bytearray([((i >> x) & 0xff) for x in [24, 16, 8, 0]])
                b += bytearray(list(param))
                b += '\0'   # Null terminate
        return b

    def run_next_test(self):
        """
        Send next test function to the target.

        """
        self.test_index += 1
        self.dep_index = 0
        if self.test_index < len(self.tests):
            name, function, deps, args = self.tests[self.test_index]
            self.log("Running: %s" % name)
            bytes = bytearray([len(deps)])
            if len(deps):
                bytes += bytearray(deps)
            bytes += bytearray([function, len(args)])
            self.parameters_to_bytes(bytes, args)
            key = bytearray([((len(bytes) >> x) & 0xff) for x in [24, 16, 8, 0]])
            #self.log("Bytes: " + " ".join(["%x '%c'" % (x, x) for x in bytes]))
            self.send_kv(key, bytes)
        else:
            self.notify_complete(True)

    @staticmethod
    def get_result(value):
        try:
            return int(value)
        except ValueError:
            ValueError("Result should return error number. Instead received %s" % value)
        return 0

    @event_callback('GO')
    def on_go(self, key, value, timestamp):
        self.run_next_test()

    @event_callback("R")
    def on_result(self, key, value, timestamp):
        """
        Handle result.

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
        Handles test execution failure. Hence marking test as skipped.

        :param key:
        :param value:
        :param timestamp:
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
