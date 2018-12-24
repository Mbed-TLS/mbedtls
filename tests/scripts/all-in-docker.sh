#!/bin/bash -eu

# all-in-docker.sh
#
# This file is part of mbed TLS (https://tls.mbed.org)
#
# Copyright (c) 2018-2019, ARM Limited, All Rights Reserved
#
# Purpose
# -------
# This runs all.sh (except for armcc) in a Docker container.
#
# Notes for users
# ---------------
# See docker_env.sh for prerequisites and other information.
#
# See also all.sh for notes about invocation of that script.

source tests/scripts/docker_env.sh

# Run tests that are possible with openly available compilers
run_in_docker tests/scripts/all.sh \
    --no-armcc \
    $@
