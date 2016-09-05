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

COUNT=1

echo
echo "$COUNT) Operating system and architecture:"
uname -a
COUNT=$((COUNT+1))

echo
if `hash armcc > /dev/null 2>&1`; then
    echo "$COUNT) armcc:"
    armcc --vsn | head -n 2
else
    echo "$COUNT) armcc not found!"
fi
COUNT=$((COUNT+1))

echo
if `hash arm-none-eabi-gcc > /dev/null 2>&1`; then
    echo "$COUNT) gcc-arm:"
    arm-none-eabi-gcc --version | head -n 1
else
    echo "$COUNT) gcc-arm not found!"
fi
COUNT=$((COUNT+1))

echo
if `hash gcc > /dev/null 2>&1`; then
    echo "$COUNT) gcc:"
    gcc --version | head -n 1
else
    echo "$COUNT) gcc not found!"
fi
COUNT=$((COUNT+1))

echo
if `hash clang > /dev/null 2>&1`; then
    echo "$COUNT) clang:"
    clang --version | head -n 2
    clang -v 2>&1 | grep Selected
else
    echo "$COUNT) clang not found!"
fi
COUNT=$((COUNT+1))

echo
if `hash ldd > /dev/null 2>&1`; then
    echo "$COUNT) libc:"
    ldd --version | head -n 1
else
    echo "$COUNT) No ldd present: can't determine libc version!"
fi
COUNT=$((COUNT+1))

echo
if `hash valgrind > /dev/null 2>&1`; then
    echo "$COUNT) valgrind:"
    valgrind --version
else
    echo "$COUNT) valgrind not found!"
fi
COUNT=$((COUNT+1))

echo
if `hash openssl > /dev/null 2>&1`; then
    echo "$COUNT) openssl:"
    openssl version
else
    echo "$COUNT) openssl not found!"
fi
COUNT=$((COUNT+1))

if [ -n "${OPENSSL+set}" ]; then
    echo
    if `hash "$OPENSSL" > /dev/null 2>&1`; then
        echo "$COUNT) $OPENSSL at environment variable 'OPENSSL':"
        $OPENSSL version
    else
        echo "$COUNT) $OPENSSL at environment variable 'OPENSSL' not found!"
    fi
    COUNT=$((COUNT+1))
fi

if [ -n "${OPENSSL_LEGACY+set}" ]; then
    echo
    if `hash "$OPENSSL_LEGACY" > /dev/null 2>&1`; then
        echo "$COUNT) $OPENSSL_LEGACY at environment variable 'OPENSSL_LEGACY':"
        $OPENSSL_LEGACY version
    else
        echo "$COUNT) $OPENSSL_LEGACY at environment variable 'OPENSSL_LEGACY' not found!"
    fi
    COUNT=$((COUNT+1))
fi

echo
if `hash gnutls-cli > /dev/null 2>&1`; then
    echo "$COUNT) gnuTLS client:"
    gnutls-cli --version | head -n 1
else
    echo "$COUNT) gnuTLS client not found!"
fi
COUNT=$((COUNT+1))

echo
if `hash gnutls-serv > /dev/null 2>&1`; then
    echo "$COUNT) gnuTLS server:"
    gnutls-serv --version | head -n 1
else
    echo "$COUNT) gnuTLS server not found!"
fi
COUNT=$((COUNT+1))

if [ -n "${GNUTLS_CLI+set}" ]; then
    echo
    if `hash "$GNUTLS_CLI" > /dev/null 2>&1`; then
        echo "$COUNT) $GNUTLS_CLI at environment variable 'GNUTLS_CLI':"
        $GNUTLS_CLI --version | head -n 1
    else
        echo "$COUNT) $GNUTLS_CLI at environment variable 'GNUTLS_CLI' not found!"
    fi
    COUNT=$((COUNT+1))
fi

if [ -n "${GNUTLS_SERV+set}" ]; then
    echo
    if `hash "$GNUTLS_SERV" > /dev/null 2>&1`; then
        echo "$COUNT) $GNUTLS_SERV at environment variable 'GNUTLS_SERV':"
        $GNUTLS_SERV --version | head -n 1
    else
        echo "$COUNT) $GNUTLS_SERV at environment variable 'GNUTLS_SERV' not found!"
    fi
    COUNT=$((COUNT+1))
fi

if [ -n "${GNUTLS_LEGACY_CLI+set}" ]; then
    echo
    if `hash "$GNUTLS_LEGACY_CLI" > /dev/null 2>&1`; then
        echo "$COUNT) $GNUTLS_LEGACY_CLI at environment variable 'GNUTLS_LEGACY_CLI':"
        $GNUTLS_LEGACY_CLI --version | head -n 1
    else
        echo "$COUNT) $GNUTLS_LEGACY_CLI at environment variable 'GNUTLS_LEGACY_CLI' not found!"
    fi
    COUNT=$((COUNT+1))
fi

if [ -n "${GNUTLS_LEGACY_SERV+set}" ]; then
    echo
    if `hash "$GNUTLS_LEGACY_SERV" > /dev/null 2>&1`; then
        echo "$COUNT) $GNUTLS_LEGACY_SERV at environment variable 'GNUTLS_LEGACY_SERV':"
        $GNUTLS_LEGACY_SERV --version | head -n 1
    else
        echo "$COUNT) $GNUTLS_LEGACY_SERV at environment variable 'GNUTLS_LEGACY_SERV' not found!"
    fi
    COUNT=$((COUNT+1))
fi

echo
if `hash dpkg > /dev/null 2>&1`; then
    echo "$COUNT) asan:"
    dpkg -s libasan2 2> /dev/null | grep -i version
    dpkg -s libasan1 2> /dev/null | grep -i version
    dpkg -s libasan0 2> /dev/null | grep -i version
else
    echo "$COUNT) No dpkg present: can't determine asan version!"
fi

echo

