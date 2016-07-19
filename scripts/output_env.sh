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
#   - version of armcc, gcc-arm and gcc compilers
#   - version of libc, clang, asan and valgrind
#   - version of gnuTLS and OpenSSL

echo
echo "1) Operating system and architecture:"
uname -a

echo
if `hash armcc` > /dev/null; then
    echo "2) armcc:"
    armcc --vsn | head -n 2
else
    echo "2) armcc not found!"
fi

echo
if `hash arm-none-eabi-gcc` > /dev/null; then
    echo
    echo "3) gcc-arm:"
    arm-none-eabi-gcc --version | head -n 1
else
    echo
    echo "3) gcc-arm not found!"
fi

echo
if `hash gcc` > /dev/null; then
    echo "4) gcc:"
    gcc --version | head -n 1
else
    echo "4) gcc not found!"
fi

echo
if `hash clang` > /dev/null; then
    echo "5) clang:"
    clang --version | head -n 2
    clang -v 2>&1 | grep Selected
else
    echo "5) clang not found!"
fi

echo
if `hash ldd` > /dev/null; then
    echo "6) libc:"
    ldd --version | head -n 1
else
    echo "6) No ldd present: can't determine libc version!"
fi

echo
if `hash valgrind` > /dev/null; then
    echo "7) valgrind:"
    valgrind --version
else
    echo "7) valgrind not found!"
fi

echo
if `hash openssl` > /dev/null; then
    echo "8) openssl:"
    openssl version
else
    echo "8) openssl not found!"
fi

echo
if `hash gnutls-cli` > /dev/null; then
    echo "9) gnuTLS client:"
    gnutls-cli --version | head -n 1
else
    echo "9) gnuTLS client not found!"
fi

echo
if `hash gnutls-serv` > /dev/null; then
    echo "10) gnuTLS server:"
    gnutls-serv --version | head -n 1
else
    echo "10) gnuTLS server not found!"
fi

echo
if `hash dpkg` > /dev/null; then
    echo "11) asan:"
    dpkg -s libasan2 2> /dev/null | grep -i version
    dpkg -s libasan1 2> /dev/null | grep -i version
    dpkg -s libasan0 2> /dev/null | grep -i version
else
    echo "11) No dpkg present: can't determine asan version!"
fi

echo
