#!/bin/bash

#
#   Create a combined (amalgamated) release with source catentated into one file under dist/
#

COMBO_HEADERS="\
    include/mbedtls/config.h \
    include/mbedtls/check_config.h \
    include/mbedtls/platform.h \
    include/mbedtls/threading.h \
    include/mbedtls/bignum.h \
    include/mbedtls/net.h \
    include/mbedtls/dhm.h \
    include/mbedtls/error.h \
    include/mbedtls/md.h \
    include/mbedtls/md_internal.h \
    include/mbedtls/md5.h \
    include/mbedtls/md2.h \
    include/mbedtls/md4.h \
    include/mbedtls/rsa.h \
    include/mbedtls/asn1.h \
    include/mbedtls/ecp.h \
    include/mbedtls/ecdsa.h \
    include/mbedtls/pk.h \
    include/mbedtls/pk_internal.h \
    include/mbedtls/x509.h \
    include/mbedtls/x509_crl.h \
    include/mbedtls/x509_crt.h \
    include/mbedtls/x509_csr.h \
    include/mbedtls/cipher.h \
    include/mbedtls/cipher_internal.h \
    include/mbedtls/ssl_ciphersuites.h \
    include/mbedtls/ecdh.h \
    include/mbedtls/sha1.h \
    include/mbedtls/sha256.h \
    include/mbedtls/sha512.h \
    include/mbedtls/aes.h \
    include/mbedtls/aesni.h \
    include/mbedtls/arc4.h \
    include/mbedtls/base64.h \
    include/mbedtls/bn_mul.h \
    include/mbedtls/camellia.h \
    include/mbedtls/ctr_drbg.h \
    include/mbedtls/des.h \
    include/mbedtls/entropy.h \
    include/mbedtls/entropy_poll.h \
    include/mbedtls/havege.h \
    include/mbedtls/memory_buffer_alloc.h \
    include/mbedtls/padlock.h \
    include/mbedtls/timing.h \
    include/mbedtls/xtea.h \
    include/mbedtls/ssl.h \
    include/mbedtls/ssl_cookie.h \
    include/mbedtls/ssl_internal.h \
    include/mbedtls/ssl_cache.h \
    include/mbedtls/ssl_ticket.h \
    include/mbedtls/debug.h \
    include/mbedtls/blowfish.h \
    include/mbedtls/camellia.h \
    include/mbedtls/ccm.h \
    include/mbedtls/gcm.h \
    include/mbedtls/pem.h \
    include/mbedtls/asn1write.h \
    include/mbedtls/hmac_drbg.h \
    include/mbedtls/pkcs12.h \
    include/mbedtls/pkcs11.h \
    include/mbedtls/pkcs5.h \
    include/mbedtls/oid.h \
    include/mbedtls/ripemd160.h \
    include/mbedtls/version.h"

COMBO_SOURCE="library/*.c"

rm -f dist/mbedtls.h dist/mbedtls.c

echo -e '/*\n *  mbedtls.h -- MbedTLS Library Header\n */\n' >>dist/mbedtls.h
for f in ${COMBO_HEADERS}
do
    echo -e '\n/********* Start of file ' ${f} ' ************/\n' >>dist/mbedtls.h
    egrep -v < ${f} '^#include.*\"|#include MBEDTLS_CONFIG_FILE/' >>dist/mbedtls.h
done
echo "Created dist/mbedtls.h"

echo -e '/*\n *  mbedtls.c -- MbedTLS Library Source\n */\n' >>dist/mbedtls.c
for f in ${COMBO_SOURCE}
do
    echo -e '\n/********* Start of file ' ${f} ' ************/\n' >>dist/mbedtls.c
    egrep -v < ${f} '^#include.*\"|#include MBEDTLS_CONFIG_FILE/' >>dist/mbedtls.c
done
echo "Created dist/mbedtls.c"

