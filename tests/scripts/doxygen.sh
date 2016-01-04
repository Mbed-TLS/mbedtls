#!/bin/sh

# Make sure the doxygen documentation builds without warnings

# Abort on errors (and uninitiliased variables)
set -eu

if [ -d library -a -d include -a -d tests ]; then :; else
    echo "Must be run from mbed TLS root" >&2
    exit 1
fi

if make apidoc > doc.out 2>doc.err; then :; else
    cat doc.err
    echo "FAIL" >&2
    exit 1;
fi

if grep warning doc.out doc.err; then
    echo "FAIL" >&2
    exit 1;
fi

make apidoc_clean
rm -f doc.out doc.err
