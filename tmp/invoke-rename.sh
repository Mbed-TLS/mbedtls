#!/bin/sh

# test result with:
# make all check
# ggrep -i --exclude-dir=mpg --exclude=.travis.yml --exclude=ChangeLog --exclude=extra-names --exclude=public-names polarssl . --exclude-dir=tmp G -v 'include|OU?=PolarSSL|PolarSSLTes' | cut -d':' -f1 | sort -u

set -eu

FILES='include/mbedtls/*.h library/*.c programs/*.c programs/*/*.c tests/suites/* configs/*.h scripts/data_files/*.fmt scripts/* tests/scripts/*'

tmp/rename.pl old2new $FILES
# re-invoke on programs including strings
