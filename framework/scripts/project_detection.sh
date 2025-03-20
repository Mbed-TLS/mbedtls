# project-detection.sh
#
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
#
# Purpose
#
# This script contains functions for shell scripts to
# help detect which project (Mbed TLS, TF-PSA-Crypto)
# or which Mbed TLS branch they are in.

# Project detection
read_project_name_file () {
    SCRIPT_DIR=$(pwd)

    PROJECT_NAME_FILE="scripts/project_name.txt"

    if read -r PROJECT_NAME < "$PROJECT_NAME_FILE"; then :; else
        echo "$PROJECT_NAME_FILE does not exist... Exiting..." >&2
        exit 1
    fi
}

in_mbedtls_repo () {
    read_project_name_file
    test "$PROJECT_NAME" = "Mbed TLS"
}

in_tf_psa_crypto_repo () {
    read_project_name_file
    test "$PROJECT_NAME" = "TF-PSA-Crypto"
}

#Branch detection
read_build_info () {
    SCRIPT_DIR=$(pwd)

    BUILD_INFO_FILE="include/mbedtls/build_info.h"

    if [ ! -f "$BUILD_INFO_FILE" ]; then
        echo "File $BUILD_INFO_FILE not found."
        exit 1
    fi

    MBEDTLS_VERSION_MAJOR=$(grep "^#define MBEDTLS_VERSION_MAJOR" "$BUILD_INFO_FILE" | awk '{print $3}')
    MBEDTLS_VERSION_MINOR=$(grep "^#define MBEDTLS_VERSION_MINOR" "$BUILD_INFO_FILE" | awk '{print $3}')

    if [ -z "$MBEDTLS_VERSION_MAJOR" ]; then
        echo "MBEDTLS_VERSION_MAJOR not found in $BUILD_INFO_FILE."
        exit 1
    fi

    if [ -z "$MBEDTLS_VERSION_MINOR" ]; then
        echo "MBEDTLS_VERSION_MINOR not found in $BUILD_INFO_FILE."
        exit 1
    fi
}

in_3_6_branch () {
    read_build_info
    test $MBEDTLS_VERSION_MAJOR = "3" && test $MBEDTLS_VERSION_MINOR = "6"
}

in_4_x_branch () {
    read_build_info
    test $MBEDTLS_VERSION_MAJOR = "4"
}
