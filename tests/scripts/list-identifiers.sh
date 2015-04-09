#!/bin/sh

set -eu

HEADERS=$( ls include/mbedtls/*.h | egrep -v 'compat-1.2|openssl|bn_mul' )

rm -f identifiers

grep '^[^ /#{]' $HEADERS | \
    sed -e 's/^[^:]*://' | \
    egrep -v '^(extern "C"|(typedef )?(struct|enum)( {)?$|};?$)' \
    > _decls

if true; then
sed -n -e 's/.* \**\([a-zA-Z_][a-zA-Z0-9_]*\)(.*/\1/p' \
       -e 's/.*(\*\(.*\))(.*/\1/p' _decls
grep -v '(' _decls | sed -e 's/\([a-zA-Z0-9_]*\)[;[].*/\1/' -e 's/.* \**//'
fi > _identifiers

if [ $( wc -l < _identifiers ) -eq $( wc -l < _decls ) ]; then
    rm _decls
    egrep -v '^(u?int(16|32|64)_t)$' _identifiers | sort > identifiers
    rm _identifiers
else
    echo "Mismatch" 2>&1
    exit 1
fi

wc -l identifiers
