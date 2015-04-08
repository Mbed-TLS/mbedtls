#!/bin/sh

# test result with:
# make all check

set -eu

tmp/analyze-names.sh
tmp/makelist.pl public-names extra-names > old2new

scripts/rename.pl -f old2new \
    library/*.c tests/suites/* configs/* scripts/data_files/*.fmt
scripts/rename.pl -f old2new -s \
    library/error.c library/version_features.c \
    library/memory_buffer_alloc.c include/mbedtls/*.h \
    library/ecp.c library/ssl_???.c tests/ssl-opt.sh \
    programs/*.c programs/*/*.c scripts/* tests/scripts/*

for i in scripts/generate_errors.pl scripts/memory.sh tests/compat.sh \
         tests/suites/test_suite_version.data configs/README.txt
do
    sed -e 's/POLARSSL/MBEDTLS/g' -e 's/polarssl/mbedtls/g' < $i > $i.tmp
    mv $i.tmp $i
done
chmod +x scripts/generate_errors.pl scripts/memory.sh tests/compat.sh

sed -e 's/server5-mbedtls_sha1/server5-sha1/' -i.tmp tests/ssl-opt.sh
rm -f tests/ssl-opt.sh.tmp

echo; echo 'Done. Remaining polarssl occurences:'
rm -f enum-consts exported-symbols extra-names identifiers macros old2new \
      prefix-enum-consts prefix-identifiers prefix-macros public-names \
      tags cscope*
grep -R --exclude-dir=.git --exclude-dir=mpg --exclude-dir=tmp \
    --exclude=.travis.yml --exclude=ChangeLog \
    -i polarssl . \
    | egrep -v 'OU?=PolarSSL|"PolarSSL|polarssl\.example' || true
