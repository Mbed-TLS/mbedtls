#!/usr/bin/env python3
#
#  Copyright The Mbed TLS Contributors
#  SPDX-License-Identifier: Apache-2.0
#
#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#

"""
Make fuzz like testing for pkcs7 tests
Given a valid DER pkcs7 file add tests to the test_suite_pkcs7.data file
 - It is expected that the pkcs7_asn1_fail( data_t *pkcs7_buf )
    function is defined in test_suite_pkcs7.function
 - This is not meant to be portable code, if anything it is meant to serve as
   documentation for showing how those ugly tests in test_suite_pkcs7.data were created
"""


import sys
from os.path import exists

pkcs7_test_file =  "../suites/test_suite_pkcs7.data"

class Test:
    def __init__(self, name, depends, func_call):
        self.name = name
        self.depends = depends
        self.func_call = func_call

    def to_string(self):
        return f"\n{self.name}\n{self.depends}\n{self.func_call}\n"

class TestData:
    mandatory_dep = "MBEDTLS_SHA256_C"
    test_name = "PKCS7 Parse Failure Invalid ASN1"
    test_function = "pkcs7_asn1_fail:"
    def __init__(self, file_name):
        self.file_name = file_name
        self.last_test_num, self.old_tests = self.read_test_file(file_name)
        self.new_tests = []

    def read_test_file(self, file):
        tests = []
        if not exists(file):
            print(f"{file} Does not exist")
            quit(1)
        f = open(file, "r")
        data = f.read()
        f.close()
        lines = [line.strip() for line in data.split('\n') if len(line.strip()) > 1]
        i = 0
        while i < len(lines):
            if "depends" in lines[i+1]:
                tests.append(Test(lines[i],lines[i+1], lines[i+2]))
                i += 3
            else:
                tests.append(Test(lines[i], None, lines[i+1]))
                i += 2
        latest_test_num = float(tests[-1].name.split('#')[1])
        return latest_test_num, tests

    def add(self, name, func_call):
        self.last_test_num += 1
        self.new_tests.append(Test(f"{self.test_name}: {name} #{self.last_test_num}", f"depends_on:{self.mandatory_dep}", f'{self.test_function}"{func_call}"'))

    def write_changes(self):
        f = open(self.file_name, 'a')
        f.write("\n")
        for t in self.new_tests:
            f.write(t.to_string())
        f.close()


def asn1_mutate(data):
    mutations = []
    reasons = []
    # we have been given an asn1 structure representing a pkcs7
    # we want to return an array of slightly modified versions of this data
    # they should be modified in a way which makes the structure invalid

    # we know that asn1 structures are:
    # |---1 byte showing data type---|----byte(s) for length of data---|---data content--|
    # we know that some data types can contain other data types

    # off the bat just add bytes to start and end of the buffer
    mutations.append(["00"] + data)
    reasons.append("Add null byte to start")
    mutations.append(data + ["00"])
    reasons.append("Add null byte to end")
    # for every asn1 entry we should attempt to:
    #    - change the data type tag
    #    - make the length longer than actual
    #    - make the length shorter than actual
    i = 0
    while i < len(data):
        tag_i = i
        leng_i = tag_i + 1
        data_i = leng_i + 1 + (int(data[leng_i][1], 16) if data[leng_i][0] == '8' else 0)
        if data[leng_i][0] == '8':
            length = int(''.join(data[leng_i + 1: data_i]), 16)
        else:
            length = int(data[leng_i], 16)

        tag = data[tag_i]
        print(f"Looking at ans1: offset {i}, tag = {tag}, length = {length}:")
        print(f"{''.join(data[data_i:data_i+length])}")
        # change tag to something else
        if tag == "02":
            # turn integers into octet strings
            new_tag = "04"
        else:
            # turn everything else into an integer
            new_tag = "02"
        mutations.append(data[:tag_i] + [new_tag] + data[leng_i:])
        reasons.append(f"Change tag {tag} to {new_tag}")

        # change lengths to too big
        # skip any edge cases which would cause carry over
        if int(data[data_i - 1], 16) < 255:
            new_length = str(hex(int(data[data_i - 1], 16) + 1))[2:]
            if len(new_length) == 1:
                new_length = "0"+new_length
            mutations.append(data[:data_i -1] + [new_length] + data[data_i:])
            reasons.append(f"Change length from {length} to {length + 1}")
            # we can add another test here for tags that contain other tags where they have more data than there containing tags account for
            if tag in ["30", "a0", "31"]:
                mutations.append(data[:data_i -1] + [new_length] + data[data_i:data_i + length] + ["00"] + data[data_i + length:])
                reasons.append(f"Change contents of tag {tag} to contain one unaccounted extra byte")
        # change lengths to too small
        if int(data[data_i - 1], 16) > 0:
            new_length = str(hex(int(data[data_i - 1], 16) - 1))[2:]
            if len(new_length) == 1:
                new_length = "0"+new_length
            mutations.append(data[:data_i -1] + [new_length] + data[data_i:])
            reasons.append(f"Change length from {length} to {length - 1}")

        # some tag types contain other tag types so we should iterate into the data
        if tag in ["30", "a0", "31"]:
            i = data_i
        else:
            i = data_i + length

    return list(zip(reasons, mutations))

if len(sys.argv) < 2:
    print(f"USAGE: {sys.argv[0]} <pkcs7_der_file>")
    quit(1)

data_file = sys.argv[1]
test_data = TestData(pkcs7_test_file)
f = open(data_file, 'rb')
data = f.read().hex()
f.close()
# make data an array of byte strings eg ['de','ad','be','ef']
data = list(map(''.join, [[data[i], data[i+1]] for i in range(0,len(data),2)]))
# returns tuples of test_names and modified data buffers
mutations = asn1_mutate(data)

print(f"made {len(mutations)} new tests")
for new_test in mutations:
    test_data.add(new_test[0], ''.join(new_test[1]))


test_data.write_changes()

