# components-build-system.sh
#
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

# This file contains test components that are executed by all.sh

################################################################
#### Build System Testing
################################################################

component_test_tf_psa_crypto_cmake_out_of_source () {
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

component_test_tf_psa_crypto_cmake_as_subdirectory () {
    msg "build: cmake 'as-subdirectory' build"
    cd programs/test/cmake_subproject
    # Note: Explicitly generate files as these are turned off in releases
    cmake -D GEN_FILES=ON .
    make
    ./cmake_subproject
}

component_tf_psa_crypto_check_generated_files () {
    msg "Check: check-generated-files, files generated with cmake" # 2s
    cmake -D CMAKE_BUILD_TYPE:String=Check -D GEN_FILES=ON "$TF_PSA_CRYPTO_ROOT_DIR"
    tests/scripts/check-generated-files.sh

    msg "Check: check-generated-files -u, files present" # 2s
    tests/scripts/check-generated-files.sh -u
    # Check that the generated files are considered up to date.
    tests/scripts/check-generated-files.sh
}
