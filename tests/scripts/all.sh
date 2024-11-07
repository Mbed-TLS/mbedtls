#! /usr/bin/env bash

# all.sh (transitional wrapper)
#
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

# This is a transitional wrapper that's only meant for the CI.
# Developers should directly invoke on or two of:
# - tests/scripts/mbedtls-all.sh ...
# - (cd tf-psa-crypto && tests/scripts/all.sh ...)
#
# During the transition, it's illegal for a tf-psa-crypto component to have
# the same name as an mbedtls components; since this wrapper handles both
# sides at once, component names need to be globally unique. Once the
# transition period is over, unicity on each side will be enough.
#
# For context, here are the steps of the transition:
# 1. We have an all.sh in tf-psa-crypto but for now we don't invoke it directly
# on the CI, only through this transitional wrapper in mbedtls. (tf-psa-crypto
# doesn't have its own CI initially and runs Mbed TLS's instead.)
# 2. We move all relevant components to tf-psa-crypto so that it gets the level of
# coverage we want. We need to make sure the new names are unique.
# 3. We change the CI job on tf-psa-crypto to stop checking out mbedtls and running
# its all.sh - instead we do the normal thing of checking out tf-psa-crypto and
# running its all.sh. (In two steps: (a) add the new job, (b) remove the old
# one.)
# 4. We remove the transitional wrapper in mbedtls and we're now free to rename
# tf-psa-crypto components as we want. If we followed a consistent naming
# pattern, this can be as simple as s/_tf_psa_crypto// in components-*.sh.

# This script must be invoked from the project's root.

# There are exactly 4 ways this is invoked in the CI:
# 1. tests/scripts/all.sh --help
# 2. tests/scripts/all.sh --list-all-components
# 3. tests/scripts/all.sh --list-components
# 4. tests/scripts/all.sh --seed 4 --keep-going single_component_name
# This wrapper does not support other invocations.

set -eu

# Cases 1-3
if [ "$#" -eq 1 ]; then
    if [ "$1" = '--help' ]; then
        # It doesn't matter which one we use, they're the same
        tests/scripts/mbedtls-all.sh "$1"
        exit 0
    fi
    if [ "$1" = '--list-all-components' -o "$1" = '--list-components' ]; then
        # Invoke both
        tests/scripts/mbedtls-all.sh "$1"
        (cd tf-psa-crypto && tests/scripts/all.sh "$1")
        exit 0
    fi
fi

if [ "$#" -ne 4 -o "${1:-unset}" != '--seed' -o "${3:-unset}" != '--keep-going' ]; then
    echo "This invocation is not supported by the transitional wrapper." >&2
    echo "See the comments at the top of $0." >&2
    exit 1
fi

# Case 4: invoke the right all.sh for this component
comp_name=$4

# Get the list of components available on each side.
COMP_MBEDTLS=$(tests/scripts/mbedtls-all.sh --list-all-components | tr '\n' ' ')
COMP_CRYPTO=$(cd tf-psa-crypto && tests/scripts/all.sh --list-all-components | tr '\n' ' ')

# tell if $1 is in space-separated list $2
is_in() {
    needle=$1
    haystack=$2
    case " $haystack " in
        *" $needle "*) echo 1;;
        *) echo 0;;
    esac
}

is_crypto=$(is_in "$comp_name" "$COMP_CRYPTO")
is_mbedtls=$(is_in "$comp_name" "$COMP_MBEDTLS")

# Component should be on exactly one side (see comment near the top).
if [ "$is_crypto" -eq 1 -a "$is_mbedtls" -eq 1 ]; then
    echo "Component '$comp_name' is both in crypto and Mbed TLS". >&2
    echo "See the comments at the top of $0." >&2
    exit 1
fi
if [ "$is_crypto" -eq 0 -a "$is_mbedtls" -eq 0 ]; then
    echo "Component '$comp_name' is neither in crypto nor in Mbed TLS". >&2
    echo "See the comments at the top of $0." >&2
    exit 1
fi


# Invoke the real thing
if [ "$is_crypto" -eq 1 ]; then
    # Make sure the path to the outcomes file is absolute. This is done by
    # pre_prepare_outcome_file() however by the time it runs we've already
    # changed the working directory, so do it now.
    if [ -n "${MBEDTLS_TEST_OUTCOME_FILE+set}" ]; then
        case "$MBEDTLS_TEST_OUTCOME_FILE" in
          [!/]*) MBEDTLS_TEST_OUTCOME_FILE="$PWD/$MBEDTLS_TEST_OUTCOME_FILE";;
        esac
        export MBEDTLS_TEST_OUTCOME_FILE
    fi
    cd tf-psa-crypto
    exec tests/scripts/all.sh "$@"
else
    exec tests/scripts/mbedtls-all.sh "$@"
fi
