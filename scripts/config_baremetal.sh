#!/bin/sh

# config_baremetal.sh
#
# This file is part of mbed TLS (https://tls.mbed.org)
#
# Copyright (c) 2017, ARM Limited, All Rights Reserved
#
# Purpose
#
# To generate config for bare metal build.
#
# Warning: the test is destructive. It modifies config via config.h.
# Original config.h is backed up as config.h.bak. Revert to it if
# modified config.h is not wanted.
#
set -eu

CONFIG_H='include/mbedtls/config.h'
CONFIG_BAK="$CONFIG_H.bak"

echo "Backing up $CONFIG_H => $CONFIG_BAK"
cp "$CONFIG_H" "$CONFIG_BAK"
scripts/config.pl full
scripts/config.pl unset MBEDTLS_NET_C
scripts/config.pl unset MBEDTLS_TIMING_C
scripts/config.pl unset MBEDTLS_FS_IO
scripts/config.pl unset MBEDTLS_ENTROPY_NV_SEED
scripts/config.pl unset MBEDTLS_HAVE_TIME
scripts/config.pl unset MBEDTLS_HAVE_TIME_DATE
scripts/config.pl set MBEDTLS_NO_PLATFORM_ENTROPY
# following things are not in the default config
scripts/config.pl unset MBEDTLS_DEPRECATED_WARNING
scripts/config.pl unset MBEDTLS_HAVEGE_C # depends on timing.c
scripts/config.pl unset MBEDTLS_THREADING_PTHREAD
scripts/config.pl unset MBEDTLS_THREADING_C
scripts/config.pl unset MBEDTLS_MEMORY_BACKTRACE # execinfo.h
scripts/config.pl unset MBEDTLS_MEMORY_BUFFER_ALLOC_C # calls exit
scripts/config.pl unset MBEDTLS_PLATFORM_TIME_ALT # depends on MBEDTLS_HAVE_TIME
scripts/config.pl unset MBEDTLS_PLATFORM_FPRINTF_ALT # depends on MBEDTLS_FS_IO
echo "Updated $CONFIG_H"

