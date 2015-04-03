#!/bin/sh

# test result with:
# make all check
# ggrep -i --exclude-dir=mpg --exclude=.travis.yml --exclude=ChangeLog --exclude=extra-names --exclude=public-names polarssl . --exclude-dir=tmp G -v 'OU?=PolarSSL|PolarSSLTes' | cut -d':' -f1 | sort -u

set -eu

tmp/analyze-names.sh
tmp/makelist.pl public-names extra-names > old2new

tmp/rename.pl old2new include/mbedtls/*.h library/*.c tests/suites/* configs/*.h scripts/data_files/*.fmt scripts/* tests/scripts/*
tmp/rename.pl old2new programs/*.c programs/*/*.c
