/*
 *  Utility for deploying parallel pipeline builds in CI.
 *
 *  Copyright (C) 2018, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

/* Windows slave labels. Used for checking if target platform is Windows. */
windows_labels = [
    "windows-tls"
]

/**
 * \brief   Create a sub job for given test and platform.
 *
 * \param test_name Descriptive test name. Like: cmake-asan-debian-x64
 * \param platform  Test platform.
 * \param docker_lbl
 *                  Docker label if platform is on a docker container. Else null.
 * \param src_stash_name
 *                  Stash name for unstashing source code.
 *
 * \return          Returns a node block that is run in parallel by the caller.
 */
def create_subjob( test_name, platform, docker_lbl, src_stash_name ) {
    if( docker_lbl ) {
        return {
            node( docker_lbl ) {
                timestamps {
                    deleteDir()
                    unstash src_stash_name
                    sh """
./tests/scripts/cibuilder.py -e ${test_name}
echo \"MBEDTLS_ROOT=.\" >> cienv.sh
docker run --rm -u \$(id -u):\$(id -g) --entrypoint /var/lib/build/tests/scripts/ciscript.sh -w /var/lib/build -v `pwd`:/var/lib/build -v /home/ubuntu/.ssh:/home/mbedjenkins/.ssh ${platform}
"""
                }
            }
        }
    } else {
        return {
            node( platform ) {
                timestamps {
                    deleteDir()
                    unstash src_stash_name
                    if( platform in windows_labels ){
                        bat """
python tests\\scripts\\cibuilder.py -e ${test_name}
echo set MBEDTLS_ROOT=. >> cienv.bat
.\\tests\\scripts\\ciscript.bat
"""
                    } else {
                        if( platform == "freebsd" ){
                            sh """
/usr/local/bin/python2.7 ./tests/scripts/cibuilder.py -e ${test_name}
echo \"export PYTHON=/usr/local/bin/python2.7\" >> cienv.sh
"""
                        } else {
                            sh """
./tests/scripts/cibuilder.py -e ${test_name}
"""
                        }
                        sh """
echo \"MBEDTLS_ROOT=.\" >> cienv.sh
./tests/scripts/ciscript.sh
"""
                    }
                }
            }
        }
    }
}

/**
 * \brief   Create steps for given campaign to execute in parallel.
 *
 * \param test_name Campaign name from cijobs.json. Like: mbedtls-commit-tests
 * \param platform_to_docker_label_map
 *                  Map platform name -> docker label
 * \param src_stash_name
 *                  Stash name for unstashing source code.
 *
 * \return          Returns map[name:node block] for parallel command.
 */
def create_parallel_jobs( campaign, platform_to_docker_label_map, src_stash_name ){
    sh """
./tests/scripts/cibuilder.py -c ${campaign} -o tests.txt
    """
    def test_jobs = [:]
    def tests = readFile 'tests.txt'
    def test_list = tests.split( '\n' )
    /* Use C style loop as it is serializable and allow calling this function
     * after loading this script from Jenkins groovy. */
    for( int i = 0; i < test_list.size(); i++ ) {
        def test = test_list[i]
        def test_details = test.split( '\\|' )
        def test_name = test_details[0]
        def platform = test_details[1]
        def docker_lbl = platform_to_docker_label_map[platform]
        def job = create_subjob( test_name, platform, docker_lbl, src_stash_name )
        if( job ){
            test_jobs[test_name] = job
        } else {
            echo "Failed to create job for ${test_name} ${platform}"
        }
    }
    return test_jobs
}

return this
