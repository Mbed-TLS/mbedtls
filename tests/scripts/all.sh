#! /usr/bin/env bash

# all.sh (transitional wrapper)
#
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

# During the transition of CI associated with the repo split,
# we want all.sh from the mbedtls repo to transparently run both
# mbedtls and tf-psa-crypto components.
# This is what this wrapper is about.
# Once the transition is over, this wrapper can be removed,
# and mbedtls-all.sh renamed again to all.sh.
#
# This wrapper is mostly for the CI's benefit. Developers probably want to
# directly invoke one or two of the following commands:
# - tests/scripts/mbedtls-all.sh ...
# - (cd tf-psa-crypto && tests/scripts/all.sh ...)

# This script must be invoked from the project's root.

set -eu

# Get the list of components available on each side.
COMP_MBEDTLS=$(tests/scripts/mbedtls-all.sh --list-all-components | sort)
COMP_CRYPTO=$(cd tf-psa-crypto && tests/scripts/all.sh --list-all-components | sort)

# Error out if any component is available on both sides
COMMON=$(comm -12 <(echo "$COMP_MBEDTLS") <(echo "$COMP_CRYPTO") | tr '\n' ' ')
if [ -n "$COMMON" ]; then
    echo "The following components are duplicated: $COMMON" >&2
    exit 2
fi

# all.sh complains when a component is requested explicitly but is not
# available. However, here we actually run two instances of all.sh, so when
# requesting one component epxlicitly, at least one instance is not going to
# know about it. So, when invoking each side, remove the other side's
# components from its command line. This is safe because we know from above
# that no component is on both sides.

# mbedtls args are global args without the crypto components
COMP_CRYPTO=$(echo $COMP_CRYPTO | tr '\n' ' ')
for arg in "$@"; do
    case " $COMP_CRYPTO " in
        *" $arg "*) ;;
        *) mbedtls_args+=( $arg ) ;;
    esac
done

# crypto args are global args without the mbedtls components
COMP_MBEDTLS=$(echo $COMP_MBEDTLS | tr '\n' ' ')
for arg in "$@"; do
    case " $COMP_MBEDTLS " in
        *" $arg "*) ;;
        *) crypto_args+=( $arg ) ;;
    esac
done

# Note: don't print debug info on what commands are being run, because we
# don't want to pollute the output especially when --list-components is used.

# call mbedtls's all.sh
set +e
tests/scripts/mbedtls-all.sh "${mbedtls_args[@]}"
mbedtls_exit=$?
set -e
if [ $mbedtls_exit -ne 0 ]; then
    echo "mbedtls-all.sh exited $mbedtls_exit" >&2
fi

# if it returned non-zero, should we keep going?
if [ $mbedtls_exit -ne 0 ]; then
     case " $@ " in
         *" --keep-going "*) ;; # fall through and run tf-psa-crypto's all.sh
         *) exit $mbedtls_exit;;
     esac
fi

# call tf-psa-crypto's all.sh
set +e
(cd tf-psa-crypto && tests/scripts/all.sh "${crypto_args[@]}")
crypto_exit=$?
set -e
if [ $crypto_exit -ne 0 ]; then
    echo "tf-psa-crypto's all.sh exited $crypto_exit" >&2
fi

# return an appropriate exit code
if [ $mbedtls_exit -ne 0 ]; then
    echo "mbedtls-all.sh exited $mbedtls_exit" >&2
    echo "Please scroll up for a summary of errors in mbedtls-all.sh" >&2
    exit $mbedtls_exit
else
    exit $crypto_exit
fi
