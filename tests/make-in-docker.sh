#!/bin/bash -eu

# make-in-docker.sh
#
# This file is part of mbed TLS (https://tls.mbed.org)
#
# Copyright (c) 2019, ARM Limited, All Rights Reserved
#
# Purpose
# -------
# This runs make in a Docker container.
#
# See also:
# - scripts/docker_env.sh for general Docker prerequisites and other information.

source tests/scripts/docker_env.sh

run_in_docker make $@
