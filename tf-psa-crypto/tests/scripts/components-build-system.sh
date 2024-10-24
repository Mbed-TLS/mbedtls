# components-build-system.sh
#
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

# This file contains test components that are executed by all.sh

################################################################
#### Build System Testing
################################################################

component_test_cmake_tf_psa_crypto_out_of_source () {
    msg "build: cmake tf-psa-crypto 'out-of-source' build"
    TF_PSA_CRYPTO_ROOT_DIR="$PWD"
    mkdir "$OUT_OF_SOURCE_DIR"
    cd "$OUT_OF_SOURCE_DIR"
    # Note: Explicitly generate files as these are turned off in releases
    cmake -D CMAKE_BUILD_TYPE:String=Check -D GEN_FILES=ON "$TF_PSA_CRYPTO_ROOT_DIR"
    make
    msg "test: cmake tf-psa-crypto 'out-of-source' build"
    make test
    cd "$TF_PSA_CRYPTO_ROOT_DIR"
    rm -rf "$OUT_OF_SOURCE_DIR"
}
