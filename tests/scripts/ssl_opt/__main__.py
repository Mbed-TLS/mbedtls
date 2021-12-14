# bash_inspect.py
#
# Copyright The Mbed TLS Contributors
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

from .bash_inspect import _SSLOptExtractor
import sys
from threading import Thread

class GenerateTestCases(Thread):
    def __init__(self, file_path):
        super().__init__()
        self._generator=_SSLOptExtractor(file_path)
        self._result=None
        self.start()
    def run(self):
        self._result=set(self._generator.extract_test_cases())
    def __call__(self):
        self.join()
        return self._result

generators=[(i,GenerateTestCases(i)) for i in sys.argv[1:]]

base_file, base_result = generators[0][0],generators[0][1]()
for k, r in generators[1:]:
    result = r()
    # result = r() - base_result
    print('{} - {} = {}'.format(k,base_file,result - base_result))
    print('{} - {} = {}'.format(base_file,k,base_result - result))

    assert result == base_result, '{} - {} = {}'.format(k,base_file,result)
