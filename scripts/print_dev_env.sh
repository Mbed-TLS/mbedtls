#!/bin/sh
#
# print_dev_env.sh
#
# This file is part of mbed TLS (https://tls.mbed.org)
#
# Copyright (c) 2014-2016, ARM Limited, All Rights Reserved
#
# Purpose
#
# To print out all the relevant information about the development encironment.
#
# This includes:
#   - architecture of the system
#   - type and version of the operationg system
#   - version of armcc, gcc-arm and gcc compilers
#   - version of libc, clang, asan and valgrind
#   - version of gnuTLS and OpenSSL

echo "\n1) Operating system and architecture:"
uname -a

if [ `which armcc` > /dev/null ]; then
    echo "\n2) armcc:"
    armcc --vsn | head -n 2
else
    echo "\n2) armcc not found!"
fi

if [ `which arm-none-eabi-gcc` > /dev/null ]; then
    echo "\n3) gcc-arm:"
    arm-none-eabi-gcc --version | head -n 1
else
    echo "\n3) gcc-arm not found!"
fi

if [ `which gcc` > /dev/null ]; then
    echo "\n4) gcc:"
    gcc --version | head -n 1
else
    echo "\n4) gcc not found!"
fi

if [ `which clang` > /dev/null ]; then
    echo "\n5) clang:"
    clang --version | head -n 2
    clang -v 2>&1 | grep Selected
else
    echo "\n5) clang not found!"
fi

if [ `which ldd` > /dev/null ]; then
    echo "\n6) libc:"
    ldd --version | head -n 1
else
    echo "\n6) No ldd present: can't determine libc version!"
fi

if [ `which valgrind` > /dev/null ]; then
    echo "\n7) valgrind:"
    valgrind --version
else
    echo "\n7) valgrind not found!"
fi

if [ `which openssl` > /dev/null ]; then
    echo "\n8) openssl:"
    openssl version
else
    echo "\n8) openssl not found!"
fi

if [ `which gnutls-cli` > /dev/null ]; then
    echo "\n9) gnuTLS client:"
    gnutls-cli --version | head -n 1
else
    echo "\n9) gnuTLS client not found!"
fi

if [ `which gnutls-serv` > /dev/null ]; then
    echo "\n10) gnuTLS server:"
    gnutls-serv --version | head -n 1
else
    echo "\n10) gnuTLS server not found!"
fi

if [ `which dpkg` > /dev/null ]; then
    echo "\n11) asan:"
    dpkg -s libasan2 2> /dev/null | grep -i version
    dpkg -s libasan1 2> /dev/null | grep -i version
    dpkg -s libasan0 2> /dev/null | grep -i version
else
    echo "\n11) No dpkg present: can't determine asan version!"
fi

echo
