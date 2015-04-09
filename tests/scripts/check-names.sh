#!/bin/sh

set -eu

tests/scripts/list-macros.sh
tests/scripts/list-enum-consts.pl
tests/scripts/list-identifiers.sh
tests/scripts/list-symbols.sh

FAIL=0

printf "Exported symbols declared in header: "
UNDECLARED=$( diff exported-symbols identifiers | sed -n -e 's/^< //p' )
if [ "x$UNDECLARED" == "x" ]; then
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
    BAD=$( grep -v '^MBEDTLS_[0-9A-Z_]*[0-9A-Z]$' $THING || true )
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
    BAD=$( grep -v '^mbedtls_[0-9a-z_]*[0-9a-z]$' $THING || true )
    if [ "x$BAD" = "x" ]; then
        echo "PASS"
    else
        echo "FAIL"
        echo "$BAD"
        FAIL=1
    fi
done

if [ "$FAIL" -eq 0 ]; then
    rm macros actual-macros enum-consts identifiers exported-symbols
    echo "PASSED"
    exit 0
else
    echo "FAILED"
    exit 1
fi
