#!/bin/sh

# Generate doxygen documentation with a full mbedtls_config.h (this ensures that every
# available flag is documented, and avoids warnings about documentation
# without a corresponding #define).
#
# /!\ This must not be a Makefile target, as it would create a race condition
# when multiple targets are invoked in the same parallel build.
#
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

set -eu

. $(dirname "$0")/project_detection.sh

if in_mbedtls_repo; then
    CONFIG_H='include/mbedtls/mbedtls_config.h'
    if [ -r $CONFIG_H ]; then :; else
        echo "$CONFIG_H not found" >&2
    fi
    if ! in_3_6_branch; then
        CRYPTO_CONFIG_H='tf-psa-crypto/include/psa/crypto_config.h'
    fi
fi

if in_tf_psa_crypto_repo; then
    CRYPTO_CONFIG_H='include/psa/crypto_config.h'
fi

if in_tf_psa_crypto_repo || (in_mbedtls_repo && ! in_3_6_branch); then
    if [ -r $CRYPTO_CONFIG_H ]; then :; else
        echo "$CRYPTO_CONFIG_H not found" >&2
        exit 1
    fi
    CRYPTO_CONFIG_BAK=${CRYPTO_CONFIG_H}.bak
    cp -p $CRYPTO_CONFIG_H $CRYPTO_CONFIG_BAK
fi

if in_mbedtls_repo; then
    CONFIG_BAK=${CONFIG_H}.bak
    cp -p $CONFIG_H $CONFIG_BAK
    scripts/config.py realfull
    make apidoc
    mv $CONFIG_BAK $CONFIG_H
elif in_tf_psa_crypto_repo; then
    scripts/config.py realfull
    TF_PSA_CRYPTO_ROOT_DIR=$PWD
    rm -rf doxygen/build-apidoc-full
    mkdir doxygen/build-apidoc-full
    cd doxygen/build-apidoc-full
    cmake -DCMAKE_BUILD_TYPE:String=Check -DGEN_FILES=ON $TF_PSA_CRYPTO_ROOT_DIR
    make tfpsacrypto-apidoc
    cd $TF_PSA_CRYPTO_ROOT_DIR
fi

if in_tf_psa_crypto_repo || (in_mbedtls_repo && ! in_3_6_branch); then
    mv $CRYPTO_CONFIG_BAK $CRYPTO_CONFIG_H
fi
