#!/bin/bash -eu

# basic-in-docker.sh
#
# Purpose
# -------
# This runs a rough equivalent of the travis.yml in a Docker container.
# The tests are run for both clang and gcc.
#
# Notes for users
# ---------------
# See docker_env.sh for prerequisites and other information.

# Copyright (C) 2006-2019, Arm Limited (or its affiliates), All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# This file is part of Mbed TLS (https://tls.mbed.org)

source tests/scripts/docker_env.sh

run_in_docker tests/scripts/recursion.pl library/*.c
run_in_docker tests/scripts/check-generated-files.sh
run_in_docker tests/scripts/check-doxy-blocks.pl
run_in_docker tests/scripts/check-names.sh
run_in_docker tests/scripts/check-files.py
run_in_docker tests/scripts/doxygen.sh

for compiler in clang gcc; do
    run_in_docker -e CC=${compiler} cmake -D CMAKE_BUILD_TYPE:String="Check" .
    run_in_docker -e CC=${compiler} make
    run_in_docker -e CC=${compiler} make test
    run_in_docker programs/test/selftest
    run_in_docker tests/scripts/test-ref-configs.pl
    run_in_docker tests/scripts/curves.pl
done
