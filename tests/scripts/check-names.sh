#!/bin/sh
#
# This file is part of mbed TLS (https://tls.mbed.org)
#
# Copyright (c) 2015-2019, ARM Limited, All Rights Reserved

set -eu

if [ $# -ne 0 ] && [ "$1" = "--help" ]; then
    cat <<EOF
$0 [-v]
This script confirms that the naming of all symbols and identifiers in mbed
TLS are consistent with the house style and are also self-consistent.

  -v    If the script fails unexpectedly, print a command trace.
EOF
    exit
fi

if grep --version|head -n1|grep GNU >/dev/null; then :; else
    echo "This script requires GNU grep.">&2
    exit 1
fi

trace=
if [ $# -ne 0 ] && [ "$1" = "-v" ]; then
  shift
  trace='-x'
  exec 2>check-names.err
  trap 'echo "FAILED UNEXPECTEDLY, status=$?";
        cat check-names.err' EXIT
  set -x
fi

printf "Analysing source code...\n"

sh $trace tests/scripts/list-macros.sh
tests/scripts/list-enum-consts.pl
sh $trace tests/scripts/list-identifiers.sh
sh $trace tests/scripts/list-symbols.sh

FAIL=0

printf "\nExported symbols declared in header: "
UNDECLARED=$( diff exported-symbols identifiers | sed -n -e 's/^< //p' )
if [ "x$UNDECLARED" = "x" ]; then
    echo "PASS"
else
    echo "FAIL"
    echo "$UNDECLARED"
    FAIL=1
fi

diff macros identifiers | sed -n -e 's/< //p' > actual-macros

for THING in actual-macros enum-consts; do
    printf "Names of $THING: "
    test -r $THING
    BAD=$( grep -E -v '^(MBEDTLS|PSA)_[0-9A-Z_]*[0-9A-Z]$' $THING || true )
    if [ "x$BAD" = "x" ]; then
        echo "PASS"
    else
        echo "FAIL"
        echo "$BAD"
        FAIL=1
    fi
done

for THING in identifiers; do
    printf "Names of $THING: "
    test -r $THING
    BAD=$( grep -E -v '^(mbedtls|psa)_[0-9a-z_]*[0-9a-z]$' $THING || true )
    if [ "x$BAD" = "x" ]; then
        echo "PASS"
    else
        echo "FAIL"
        echo "$BAD"
        FAIL=1
    fi
done

printf "Likely typos: "
sort -u actual-macros enum-consts > _caps
HEADERS=$( ls include/mbedtls/*.h include/psa/*.h | egrep -v 'compat-1\.3\.h' )
NL='
'
sed -n 's/MBED..._[A-Z0-9_]*/\'"$NL"'&\'"$NL"/gp \
    $HEADERS library/*.c \
    | grep MBEDTLS | sort -u > _MBEDTLS_XXX
TYPOS=$( diff _caps _MBEDTLS_XXX | sed -n 's/^> //p' \
            | egrep -v 'XXX|__|_$|^MBEDTLS_.*CONFIG_FILE$' || true )
rm _MBEDTLS_XXX _caps
if [ "x$TYPOS" = "x" ]; then
    echo "PASS"
else
    echo "FAIL"
    echo "$TYPOS"
    FAIL=1
fi

if [ -n "$trace" ]; then
  set +x
  trap - EXIT
  rm check-names.err
fi

printf "\nOverall: "
if [ "$FAIL" -eq 0 ]; then
    rm macros actual-macros enum-consts identifiers exported-symbols
    echo "PASSED"
    exit 0
else
    echo "FAILED"
    exit 1
fi
