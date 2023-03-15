#!/usr/bin/env python3

"""
Generate main file, individual apps and solution files for MS Visual Studio 2013.

"""

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


import glob
import hashlib
import os
import itertools
import sys
import pathlib
import jinja2

import mbedtls_dev.build_tree as build_tree

build_tree.chdir_to_root()


CONFIGURATIONS = list(itertools.product(
    ['Debug', 'Release'], ['Win32', 'x64']))

# Directories to add to the include path.
# Order matters in case there are files with the same name in more than
# one directory: the compiler will use the first match.
INCLUDE_DIRECTORIES = [
    'include',
    '3rdparty/everest/include/',
    '3rdparty/everest/include/everest',
    '3rdparty/everest/include/everest/vs2013',
    '3rdparty/everest/include/everest/kremlib',
    'tests/include'
]

# Directories to add to the include path when building the library, but not
# when building tests or applications.
LIBRARY_INCLUDE_DIRECTORIES = [
    'library'
]

VSX_DIR = "visualc/VS2013"

class VcProject:
    """ Generate vc project files(.vcxproj)
    """
    def __init__(self, path, template_env, **kwargs) -> None:
        self.__configurations = kwargs.get('configurations', CONFIGURATIONS)
        self.__path = path
        self.__output_dir = os.path.abspath(kwargs.get('output_dir', VSX_DIR))

        def to_relpath(arg, def_val=None):
            return [os.path.relpath(os.path.abspath(i), self.__output_dir)
                    for i in kwargs.get(arg, def_val or [])]

        self.__sources = to_relpath('sources')
        self.__include_directories = to_relpath(
            'include_directories', INCLUDE_DIRECTORIES)
        self.__headers = to_relpath('headers')

        self.__guid = kwargs.get('guid', self._get_guid())
        self.__ref_proj = kwargs.get('ref_proj', None)
        self.__configuration_type = kwargs.get(
            'configuration_type', 'Application')
        self.__template_env = template_env

    def _get_guid(self):
        name = 'mbedTLS:{}'.format(self.__path)
        h = hashlib.md5(name.encode('utf-8')).hexdigest().upper()
        return '{{{}-{}-{}-{}-{}}}'.format(h[:8], h[8:12], h[12:16], h[16:20], h[20:])

    @property
    def configurations(self):
        return self.__configurations

    @property
    def configuration_type(self):
        return self.__configuration_type

    @property
    def name(self):
        return os.path.basename(self.__path)

    @property
    def guid(self):
        return self.__guid

    @property
    def ref_proj(self):
        return self.__ref_proj

    @property
    def headers(self):
        return self.__headers

    @property
    def sources(self):
        return self.__sources

    @property
    def output_dir(self):
        return self.__output_dir

    @property
    def include_directories(self):
        return self.__include_directories

    def save(self):
        with open(os.path.join(self.output_dir, self.name + '.vcxproj'), 'w',
                  newline='\r\n', encoding="utf-8") as f:
            template = self.__template_env.get_template('vs2013-vcxproj.jinja2')
            f.write(template.render(project=self))


class VcSolution:
    """Generate VS solution file(.sln)
    """
    def __init__(self, name, template_env, **kwargs) -> None:
        self.__output_dir = os.path.abspath(kwargs.get('output_dir', VSX_DIR))
        self.__configurations = kwargs.get('configurations', CONFIGURATIONS)
        self.__projects = kwargs.get('projects', [])
        self.__template_env = template_env
        self.__name = name

    def save(self):
        with open(os.path.join(self.__output_dir, self.__name + '.sln'), 'w',
                  newline='\r\n', encoding="utf-8") as f:
            template = self.__template_env.get_template('vs2013-sln.jinja2')
            f.write(template.render(solution=self))
        for proj in self.projects:
            proj.save()

    @property
    def projects(self):
        return self.__projects

    @property
    def configurations(self):
        return self.__configurations


def generate_main_project(template_env):
    """Generate mbedTLS.vcxproj, that is main project.

    Args:
        template_env (jinja2.TemplateEnv): Jinja2 template environment

    Returns:
        VcProject: main project object.
    """
    excluded_files = [
        pathlib.Path('3rdparty/everest/library/Hacl_Curve25519.c')
    ]
    source_dir = 'library'

    thirdparty_header_dirs = [
        '3rdparty/everest/include/everest'
    ]
    thirdparty_source_dirs = [
        '3rdparty/everest/library',
        '3rdparty/everest/library/kremlib',
        '3rdparty/everest/library/legacy'
    ]

    header_dirs = [
        'include/mbedtls',
        'include/psa',
        'tests/include/test',
        'tests/include/test/drivers',
        'library'
    ] + thirdparty_header_dirs

    headers = set({})
    for header_dir in header_dirs:
        headers |= set(glob.glob("{}/*.h".format((header_dir))))

    source_dirs = [
        'library',
        'tests/src',
        'tests/src/drivers'
    ] + thirdparty_source_dirs

    sources = []
    for source_dir in source_dirs:
        sources.extend(glob.glob("{}/*.c".format((source_dir))))

    headers = {os.path.abspath(header)
               for header in headers if pathlib.Path(header) not in excluded_files}
    sources = {os.path.abspath(source)
               for source in sources if pathlib.Path(source) not in excluded_files}
    return VcProject('mbedTLS', template_env,
                     guid='{46CF2D25-6A36-4189-B59C-E4815388E554}',
                     configuration_type='StaticLibrary',
                     sources=sorted(sources),
                     headers=sorted(headers),
                     include_directories=LIBRARY_INCLUDE_DIRECTORIES + INCLUDE_DIRECTORIES)


def generate_application_projects(template_env, ref_proj=None):
    """Generate application projects of MBedTLS

    Args:
        template_env (jinja2.TemplateEnv): Jinja2 template environment
        ref_proj (VcProject, optional): Reference project. Defaults to None.

    Yields:
        VcProject: application projects.
    """
    programs_dir = 'programs'
    with open(os.path.join(programs_dir, 'Makefile')) as f:
        makefile_contents = f.read()
    start = makefile_contents.find('APPS =') + len('APPS =')
    end = makefile_contents.find('#', start)
    app_list_str = makefile_contents[start:end].replace('\\', '').strip()

    for path in app_list_str.split():
        sources = [os.path.abspath(os.path.join(
            programs_dir, "{}.c".format((path))))]
        if path in ('ssl/ssl_client2', 'ssl/ssl_server2', 'test/query_compile_time_config'):
            sources.append(os.path.abspath(os.path.join(
                programs_dir, "test/query_config.c")))
        if path in ('ssl/ssl_client2', 'ssl/ssl_server2'):
            sources.append(os.path.abspath(
                os.path.join(programs_dir, "ssl/ssl_test_lib.c")))
        yield VcProject(path, template_env, ref_proj=ref_proj, sources=sources,
                        include_directories=INCLUDE_DIRECTORIES)


def main():
    template_loader = jinja2.FileSystemLoader(
        searchpath=os.path.join(build_tree.guess_mbedtls_root(), 'scripts', 'data_files'))
    template_env = jinja2.Environment(
        loader=template_loader, lstrip_blocks=True, trim_blocks=True)

    os.makedirs(VSX_DIR, exist_ok=True)
    main_proj = generate_main_project(template_env)
    projects = [main_proj] + \
        list(generate_application_projects(template_env, ref_proj=main_proj))
    solution = VcSolution('mbedTLS', template_env,
                          projects=projects, configurations=CONFIGURATIONS)
    solution.save()


if __name__ == '__main__':
    sys.exit(main())
