#!/bin/sh
#
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

. "${0%/*}/../demo_common.sh"

msg <<'EOF'
This program demonstrates the use of the PSA cryptography interface to
perform a key agreement operation.
EOF

depends_on MBEDTLS_PSA_CRYPTO_C MBEDTLS_ECP_C MBEDTLS_ECP_DP_SECP256R1_ENABLED \
!MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER

program="${0%/*}"/psa_key_agreement

"$program"

cleanup