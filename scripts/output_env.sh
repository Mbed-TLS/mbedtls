#!/bin/sh
#
# output_env.sh
#
# This file is part of mbed TLS (https://tls.mbed.org)
#
# Copyright (c) 2016, ARM Limited, All Rights Reserved
#
# Purpose
#
# To print out all the relevant information about the development environment.
#
# This includes:
#   - architecture of the system
#   - type and version of the operating system
#   - version of armcc, clang, gcc-arm and gcc compilers
#   - version of libc, clang, asan and valgrind if installed
#   - version of gnuTLS and OpenSSL

echo
echo "* Operating system and architecture:"
uname -a

echo
if `hash armcc > /dev/null 2>&1`; then
    echo "* armcc:"
    armcc --vsn | head -n 2
else
    echo "* armcc not found!"
fi

echo
if `hash arm-none-eabi-gcc > /dev/null 2>&1`; then
    echo "* gcc-arm:"
    arm-none-eabi-gcc --version | head -n 1
else
    echo "* gcc-arm not found!"
fi

echo
if `hash gcc > /dev/null 2>&1`; then
    echo "* gcc:"
    gcc --version | head -n 1
else
    echo "* gcc not found!"
fi

echo
if `hash clang > /dev/null 2>&1`; then
    echo "* clang:"
    clang --version | head -n 2
    clang -v 2>&1 | grep Selected
else
    echo "* clang not found!"
fi

echo
if `hash ldd > /dev/null 2>&1`; then
    echo "* libc:"
    ldd --version | head -n 1
else
    echo "* No ldd present: can't determine libc version!"
fi

echo
if `hash valgrind > /dev/null 2>&1`; then
    echo "* valgrind:"
    valgrind --version
else
    echo "* valgrind not found!"
fi

echo
if `hash openssl > /dev/null 2>&1`; then
    echo "* openssl:"
    openssl version
else
    echo "* openssl not found!"
fi

if [ -n "${OPENSSL+set}" ]; then
    echo
    if `hash "$OPENSSL" > /dev/null 2>&1`; then
        echo "* $OPENSSL at environment variable 'OPENSSL':"
        $OPENSSL version
    else
        echo "* $OPENSSL at environment variable 'OPENSSL' not found!"
    fi
fi

if [ -n "${OPENSSL_LEGACY+set}" ]; then
    echo
    if `hash "$OPENSSL_LEGACY" > /dev/null 2>&1`; then
        echo "* $OPENSSL_LEGACY at environment variable 'OPENSSL_LEGACY':"
        $OPENSSL_LEGACY version
    else
        echo "* $OPENSSL_LEGACY at environment variable 'OPENSSL_LEGACY' not found!"
    fi
fi

echo
if `hash gnutls-cli > /dev/null 2>&1`; then
    echo "* gnuTLS client:"
    gnutls-cli --version | head -n 1
else
    echo "* gnuTLS client not found!"
fi

echo
if `hash gnutls-serv > /dev/null 2>&1`; then
    echo "* gnuTLS server:"
    gnutls-serv --version | head -n 1
else
    echo "* gnuTLS server not found!"
fi

if [ -n "${GNUTLS_CLI+set}" ]; then
    echo
    if `hash "$GNUTLS_CLI" > /dev/null 2>&1`; then
        echo "* $GNUTLS_CLI at environment variable 'GNUTLS_CLI':"
        $GNUTLS_CLI --version | head -n 1
    else
        echo "* $GNUTLS_CLI at environment variable 'GNUTLS_CLI' not found!"
    fi
fi

if [ -n "${GNUTLS_SERV+set}" ]; then
    echo
    if `hash "$GNUTLS_SERV" > /dev/null 2>&1`; then
        echo "* $GNUTLS_SERV at environment variable 'GNUTLS_SERV':"
        $GNUTLS_SERV --version | head -n 1
    else
        echo "* $GNUTLS_SERV at environment variable 'GNUTLS_SERV' not found!"
    fi
fi

if [ -n "${GNUTLS_LEGACY_CLI+set}" ]; then
    echo
    if `hash "$GNUTLS_LEGACY_CLI" > /dev/null 2>&1`; then
        echo "* $GNUTLS_LEGACY_CLI at environment variable 'GNUTLS_LEGACY_CLI':"
        $GNUTLS_LEGACY_CLI --version | head -n 1
    else
        echo "* $GNUTLS_LEGACY_CLI at environment variable 'GNUTLS_LEGACY_CLI' not found!"
    fi
fi

if [ -n "${GNUTLS_LEGACY_SERV+set}" ]; then
    echo
    if `hash "$GNUTLS_LEGACY_SERV" > /dev/null 2>&1`; then
        echo "* $GNUTLS_LEGACY_SERV at environment variable 'GNUTLS_LEGACY_SERV':"
        $GNUTLS_LEGACY_SERV --version | head -n 1
    else
        echo "* $GNUTLS_LEGACY_SERV at environment variable 'GNUTLS_LEGACY_SERV' not found!"
    fi
fi

echo
if `hash dpkg > /dev/null 2>&1`; then
    echo "* asan:"
    dpkg -s libasan2 2> /dev/null | grep -i version
    dpkg -s libasan1 2> /dev/null | grep -i version
    dpkg -s libasan0 2> /dev/null | grep -i version
else
    echo "* No dpkg present: can't determine asan version!"
fi

echo

