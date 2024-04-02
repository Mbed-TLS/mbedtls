#!/bin/sh
#
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

. "${0%/*}/../demo_common.sh"

msg <<'EOF'
This program demonstrates the use of the PSA cryptography interface to
demonstrate a digital signature operation. In this example psa_sign_hash()
is used for signing, and psa_verify_hash() is used for the verification.
EOF

depends_on MBEDTLS_PSA_CRYPTO_C MBEDTLS_ECDSA_C !MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER

program="${0%/*}"/psa_sign_verify

"$program"

cleanup