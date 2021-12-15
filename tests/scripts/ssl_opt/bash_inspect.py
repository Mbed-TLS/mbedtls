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

import os
import re
import tempfile
from subprocess import Popen, PIPE, check_output

from .core import OptionTestCreateState

SSL_OPT_FUNC_BODY = r"""(){
    python3 - <<END
import shlex
try:
    if $#:
        args=[$(printf "r''' %s '''," "$@")]
    else:
        args=[]
    source = '${INSPECT_SOURCE}' if '${BASH_SOURCE[1]}' == '${INSPECT_TMP}' else '${BASH_SOURCE[1]}'
    print('"{}"'.format(source),'${BASH_LINENO}','"$FUNCNAME"',[i[1:-1] for i in args],sep=',')
except :
    raise
END
}
"""


class InspectFail(Exception):
    pass


def run_bash_script_iter(script_file, cwd=None, env=None):
    if env is not None:
        env = os.environ + env
    with Popen(['bash', '-c', 'source ' + script_file], stdout=PIPE,
               bufsize=1, env=env, cwd=cwd, universal_newlines=True) as p:
        yield from p.stdout
        ret = p.wait()
        if ret:
            raise InspectFail('Script running fail {}'.format(p.stderr))


def run_bash_script(script, cwd=None, env=None):
    if env is not None:
        env = os.environ + env

    return check_output(['bash', '-c', script], bufsize=1, env=env, cwd=cwd, universal_newlines=True)


class _SSLOptExtractor:
    def __init__(self, file_path) -> None:
        regex = re.compile(r'''(?P<padding0>(.|\n)*?)
            (?P<header>\#\ default\ values,\ can\ be\ overridden\ by\ the\ environment\n(.|\n)*?)
            (?P<body>\#\ Basic\ test\n(.|\n)*?\n\#\ Final\ report\n)
            (?P<padding1>(.|\n)*)
        ''', re.VERBOSE)
        with open(file_path) as f:
            match_obj = regex.match(f.read())
        if match_obj is None:
            raise InspectFail(
                "{} is not match ssl-opt format".format(file_path))
        self.working_dir = os.path.dirname(file_path)
        self._file_path = file_path
        for k, v in match_obj.groupdict().items():
            setattr(self, '_' + k, v)

    def _construct_head(self):
        def get_definitions(script):
            functions = set()
            variables = set()
            regex = re.compile(r'^declare \-('
                               + r'([xirAa\-]r?\ (?P<var>\w+)(.*))'
                               + r'|([f]\ (?P<func>\w+))'
                               + r')$', re.M)
            regex = re.compile(r'^declare \-('
                               + r'([xirAa\-]r?\ (?P<var>\w+)(.*?))'
                               + r'|([f]\ (?P<func>\w+))'
                               + r')$', re.M)
            for m in regex.finditer(run_bash_script(script + '\ndeclare -p;declare -F', cwd=self.working_dir)):
                if m.group('var'):
                    variables |= {m.group('var'), }
                if m.group('func'):
                    functions |= {m.group('func'), }
            return functions, variables

        regex = re.compile(r'(# ssl_opt_inspect:reserve_vars:(?P<vars>.*?)\n)'
                           r'|(# ssl_opt_inspect:reserve_funcs:(?P<funcs>.*?)\n)')
        reserve_variables = set({})
        reserve_functions = set({})
        for m in regex.finditer(self._header):
            if m.group('vars'):
                reserve_variables |= set(m.group('vars').strip().split())
            if m.group('funcs'):
                reserve_functions |= set(m.group('funcs').strip().split())
        basic_functions, basic_variables = get_definitions('')
        end_functions, end_variables = get_definitions(self._header)
        functions = end_functions - basic_functions - reserve_functions
        variables = end_variables - basic_variables - reserve_variables
        reserve_functions &= end_functions
        reserve_variables &= end_variables
        ret = []
        for func in functions:
            ret.append(func + SSL_OPT_FUNC_BODY)
        for var in variables:
            ret.append(r'{var}=\${var}'.format(var=var))
        if reserve_variables:
            regex = re.compile(r'^declare \-[xirAa\-]r?\ ', re.M)
            script = self._header + \
                ('\ndeclare -p {}'.format(' '.join(reserve_variables)))
            strings = run_bash_script(script, cwd=self.working_dir)
            ret.append(regex.sub('', strings))
            # for line in run_bash_script(self._header + ('\ndeclare -p {}'.format(' '.join(reserve_variables)))):
            #     print(repr(line))

        if reserve_functions:
            script = self._header + \
                ('\ndeclare -f {}'.format(' '.join(reserve_functions)))
            ret.append(run_bash_script(script, cwd=self.working_dir))
        return '\n'.join(ret)
        # print(repr(line))

    def extract_commands(self):
        tmp_file = tempfile.mktemp()
        construct_head = self._construct_head()
        line_no = self._padding0.count('\n') + self._header.count('\n')
        # print(line_no)
        with open(tmp_file, 'w') as f:
            f.write('set -e\n')
            f.write('INSPECT_SOURCE={}\n'.format(self._file_path))
            f.write('INSPECT_TMP={}\n'.format(tmp_file))
            f.write(construct_head)
            f.write('\n'*(line_no - construct_head.count('\n')-3))
            f.write(self._body)
        for line in run_bash_script_iter(tmp_file, cwd=self.working_dir):
            yield eval(line)

    def extract_test_cases(self):
        cmds = set()
        state = OptionTestCreateState()
        for filename, lineno, cmd, args in self.extract_commands():
            case = state(cmd, *args, filename=filename, lineno=lineno)
            cmds.add(cmd)
            if case is None:
                continue
            yield case
        assert not state.commands(), state.commands()
        return cmds

