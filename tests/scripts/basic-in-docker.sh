#!/bin/bash -eu

# basic-in-docker.sh
#
# This file is part of mbed TLS (https://tls.mbed.org)
#
# Copyright (c) 2018-2019, ARM Limited, All Rights Reserved
#
# Purpose
# -------
# This runs a rough equivalent of the travis.yml in a Docker container.
# The tests are run for both clang and gcc.
#
# Notes for users
# ---------------
# See docker_env.sh for prerequisites and other information.

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
    run_in_docker -e OSSL_NO_DTLS=1 tests/compat.sh
    run_in_docker tests/ssl-opt.sh -e '\(DTLS\|SCSV\).*openssl'
    run_in_docker tests/scripts/test-ref-configs.pl
    run_in_docker tests/scripts/curves.pl
    run_in_docker tests/scripts/key-exchanges.pl
done
