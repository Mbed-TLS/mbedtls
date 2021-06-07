#!/bin/sh

make clean
sed -i 's/GENERATE_XML           = NO/GENERATE_XML           = YES/g' doxygen/mbedtls.doxyfile
scripts/config.py full
cd doxygen
doxygen mbedtls.doxyfile
cd ..
python3 apply_MBEDTLS_PRIVATE.py
git checkout include/mbedtls/config.h doxygen/mbedtls.doxyfile

make clean
sed -i 's/GENERATE_XML           = NO/GENERATE_XML           = YES/g' doxygen/mbedtls.doxyfile
scripts/config.py set MBEDTLS_ECP_RESTARTABLE
scripts/config.py unset MBEDTLS_SSL_KEEP_PEER_CERTIFICATE
scripts/config.py unset MBEDTLS_HAVE_TIME
cd doxygen
doxygen mbedtls.doxyfile
cd ..
python3 apply_MBEDTLS_PRIVATE.py
git checkout include/mbedtls/config.h doxygen/mbedtls.doxyfile

make clean
sed -i 's/GENERATE_XML           = NO/GENERATE_XML           = YES/g' doxygen/mbedtls.doxyfile
scripts/config.py realfull
cd doxygen
doxygen mbedtls.doxyfile
cd ..
python3 apply_MBEDTLS_PRIVATE.py
git checkout include/mbedtls/config.h doxygen/mbedtls.doxyfile

