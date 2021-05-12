#!/bin/sh

make clean
sed -i 's/GENERATE_XML           = NO/GENERATE_XML           = YES/g' doxygen/mbedtls.doxyfile
scripts/config.py full
cd doxygen
doxygen mbedtls.doxyfile
cd ..
python3 apply_MBEDTLS_PRIVATE.py
git checkout include/mbedtls/config.h doxygen/mbedtls.doxyfile
