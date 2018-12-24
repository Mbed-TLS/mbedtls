#!/bin/bash -eu

# compat-in-docker.sh
#
# This file is part of mbed TLS (https://tls.mbed.org)
#
# Copyright (c) 2019, ARM Limited, All Rights Reserved
#
# Purpose
# -------
# This runs compat.sh in a Docker container.
#
# Notes for users
# ---------------
# If OPENSSL_CMD, GNUTLS_CLI, or GNUTLS_SERV are specified the path must
# correspond to an executable inside the Docker container. The special
# values "next" (OpenSSL only) and "legacy" are also allowed as shorthand
# for the installations inside the container.
#
# See also:
# - scripts/docker_env.sh for general Docker prerequisites and other information.
# - compat.sh for notes about invocation of that script.

source tests/scripts/docker_env.sh

case "${OPENSSL_CMD:-default}" in
    "legacy")  export OPENSSL_CMD="/usr/local/openssl-1.0.1j/bin/openssl";;
    "next")    export OPENSSL_CMD="/usr/local/openssl-1.1.1a/bin/openssl";;
    *) ;;
esac

case "${GNUTLS_CLI:-default}" in
    "legacy")  export GNUTLS_CLI="/usr/local/gnutls-3.3.8/bin/gnutls-cli";;
    "next")  export GNUTLS_CLI="/usr/local/gnutls-3.6.5/bin/gnutls-cli";;
    *) ;;
esac

case "${GNUTLS_SERV:-default}" in
    "legacy")  export GNUTLS_SERV="/usr/local/gnutls-3.3.8/bin/gnutls-serv";;
    "next")  export GNUTLS_SERV="/usr/local/gnutls-3.6.5/bin/gnutls-serv";;
    *) ;;
esac

run_in_docker \
    -e M_CLI \
    -e M_SRV \
    -e GNUTLS_CLI \
    -e GNUTLS_SERV \
    -e OPENSSL_CMD \
    -e OSSL_NO_DTLS \
    tests/compat.sh \
    $@
