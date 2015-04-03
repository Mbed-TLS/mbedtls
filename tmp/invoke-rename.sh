#!/bin/sh

# test result with:
# make all check

set -eu

tmp/analyze-names.sh
tmp/makelist.pl public-names extra-names > old2new

tmp/rename.pl    old2new library/*.c tests/suites/* tests/ssl-opt.sh \
                 configs/* scripts/data_files/*.fmt
tmp/rename.pl -s old2new library/error.c library/version_features.c \
                 library/memory_buffer_alloc.c include/mbedtls/*.h \
                 library/ecp.c \
                 programs/*.c programs/*/*.c scripts/* tests/scripts/*

for i in scripts/generate_errors.pl scripts/memory.sh tests/compat.sh \
         tests/suites/test_suite_version.data configs/README.txt
do
    sed -e 's/POLARSSL/MBEDTLS/g' -e 's/polarssl/mbedtls/g' < $i > $i.tmp
    mv $i.tmp $i
done
chmod +x scripts/generate_errors.pl scripts/memory.sh tests/compat.sh

echo; echo 'Done. Remaining polarssl occurences:'
rm -f enum-consts exported-symbols extra-names identifiers macros old2new \
      prefix-enum-consts prefix-identifiers prefix-macros public-names \
      tags cscope*
grep -R --exclude-dir=.git --exclude-dir=mpg --exclude-dir=tmp \
    --exclude=.travis.yml --exclude=ChangeLog \
    -i polarssl . \
    | egrep -v 'OU?=PolarSSL|"PolarSSL|polarssl\.example' || true
