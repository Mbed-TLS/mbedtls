#!/bin/sh

# Measure heap usage (and performance) of ECC operations with various values of
# the relevant tunable compile-time parameters.
#
# Usage (preferably on a 32-bit platform):
# cmake -D CMAKE_BUILD_TYPE=Release .
# scripts/ecc-heap.sh | tee ecc-heap.log

set -eu

CONFIG_H='include/polarssl/config.h'

if [ -r $CONFIG_H ]; then :; else
    echo "$CONFIG_H not found" >&2
    exit 1
fi

if grep -i cmake Makefile >/dev/null; then :; else
    echo "Needs Cmake" >&2
    exit 1
fi

if git status | grep -F $CONFIG_H >/dev/null 2>&1; then
    echo "config.h not clean" >&2
    exit 1
fi

CONFIG_BAK=${CONFIG_H}.bak
cp $CONFIG_H $CONFIG_BAK

cat << EOF >$CONFIG_H
#define POLARSSL_PLATFORM_C
#define POLARSSL_PLATFORM_MEMORY
#define POLARSSL_MEMORY_BUFFER_ALLOC_C
#define POLARSSL_MEMORY_DEBUG

#define POLARSSL_TIMING_C

#define POLARSSL_BIGNUM_C
#define POLARSSL_ECP_C
#define POLARSSL_ASN1_PARSE_C
#define POLARSSL_ASN1_WRITE_C
#define POLARSSL_ECDSA_C
#define POLARSSL_ECDH_C

#define POLARSSL_ECP_DP_SECP192R1_ENABLED
#define POLARSSL_ECP_DP_SECP224R1_ENABLED
#define POLARSSL_ECP_DP_SECP256R1_ENABLED
#define POLARSSL_ECP_DP_SECP384R1_ENABLED
#define POLARSSL_ECP_DP_SECP521R1_ENABLED
#define POLARSSL_ECP_DP_M255_ENABLED

#include "check_config.h"

//#define POLARSSL_ECP_WINDOW_SIZE            6
//#define POLARSSL_ECP_FIXED_POINT_OPTIM      1
EOF

for F in 0 1; do
    for W in 2 3 4 5 6; do
        scripts/config.pl set POLARSSL_ECP_WINDOW_SIZE $W
        scripts/config.pl set POLARSSL_ECP_FIXED_POINT_OPTIM $F
        make benchmark >/dev/null 2>&1
        echo "fixed point optim = $F, max window size = $W"
        echo "--------------------------------------------"
        programs/test/benchmark
    done
done

# cleanup

mv $CONFIG_BAK $CONFIG_H
make clean
