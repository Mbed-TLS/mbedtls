#!/bin/sh

# 70-psa-curve.sh
#
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#


run_test_psa() {
    requires_config_enabled MBEDTLS_USE_PSA_CRYPTO
    run_test    "PSA-supported ciphersuite: $1" \
                "$P_SRV debug_level=3 force_version=tls12" \
                "$P_CLI debug_level=3 force_version=tls12 force_ciphersuite=$1" \
                0 \
                -c "Successfully setup PSA-based decryption cipher context" \
                -c "Successfully setup PSA-based encryption cipher context" \
                -c "PSA calc verify" \
                -c "calc PSA finished" \
                -s "Successfully setup PSA-based decryption cipher context" \
                -s "Successfully setup PSA-based encryption cipher context" \
                -s "PSA calc verify" \
                -s "calc PSA finished" \
                -C "Failed to setup PSA-based cipher context"\
                -S "Failed to setup PSA-based cipher context"\
                -s "Protocol is TLSv1.2" \
                -c "Perform PSA-based ECDH computation."\
                -c "Perform PSA-based computation of digest of ServerKeyExchange" \
                -S "error" \
                -C "error"
}

run_test_psa_force_curve() {
    requires_config_enabled MBEDTLS_USE_PSA_CRYPTO
    run_test    "PSA - ECDH with $1" \
                "$P_SRV debug_level=4 force_version=tls12 curves=$1" \
                "$P_CLI debug_level=4 force_version=tls12 force_ciphersuite=TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256 curves=$1" \
                0 \
                -c "Successfully setup PSA-based decryption cipher context" \
                -c "Successfully setup PSA-based encryption cipher context" \
                -c "PSA calc verify" \
                -c "calc PSA finished" \
                -s "Successfully setup PSA-based decryption cipher context" \
                -s "Successfully setup PSA-based encryption cipher context" \
                -s "PSA calc verify" \
                -s "calc PSA finished" \
                -C "Failed to setup PSA-based cipher context"\
                -S "Failed to setup PSA-based cipher context"\
                -s "Protocol is TLSv1.2" \
                -c "Perform PSA-based ECDH computation."\
                -c "Perform PSA-based computation of digest of ServerKeyExchange" \
                -S "error" \
                -C "error"
}


# Test ciphersuites which we expect to be fully supported by PSA Crypto
# and check that we don't fall back to Mbed TLS' internal crypto primitives.
run_test_psa TLS-ECDHE-ECDSA-WITH-AES-128-CCM
run_test_psa TLS-ECDHE-ECDSA-WITH-AES-128-CCM-8
run_test_psa TLS-ECDHE-ECDSA-WITH-AES-256-CCM
run_test_psa TLS-ECDHE-ECDSA-WITH-AES-256-CCM-8
run_test_psa TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256
run_test_psa TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384
run_test_psa TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA
run_test_psa TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256
run_test_psa TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384

requires_config_enabled MBEDTLS_ECP_DP_SECP521R1_ENABLED
run_test_psa_force_curve "secp521r1"
requires_config_enabled MBEDTLS_ECP_DP_BP512R1_ENABLED
run_test_psa_force_curve "brainpoolP512r1"
requires_config_enabled MBEDTLS_ECP_DP_SECP384R1_ENABLED
run_test_psa_force_curve "secp384r1"
requires_config_enabled MBEDTLS_ECP_DP_BP384R1_ENABLED
run_test_psa_force_curve "brainpoolP384r1"
requires_config_enabled MBEDTLS_ECP_DP_SECP256R1_ENABLED
run_test_psa_force_curve "secp256r1"
requires_config_enabled MBEDTLS_ECP_DP_SECP256K1_ENABLED
run_test_psa_force_curve "secp256k1"
requires_config_enabled MBEDTLS_ECP_DP_BP256R1_ENABLED
run_test_psa_force_curve "brainpoolP256r1"
requires_config_enabled MBEDTLS_ECP_DP_SECP224R1_ENABLED
run_test_psa_force_curve "secp224r1"
## SECP224K1 is buggy via the PSA API
## (https://github.com/ARMmbed/mbedtls/issues/3541),
## so it is disabled in PSA even when it's enabled in Mbed TLS.
## The proper dependency would be on PSA_WANT_ECC_SECP_K1_224 but
## dependencies on PSA symbols in ssl-opt.sh are not implemented yet.
#requires_config_enabled MBEDTLS_ECP_DP_SECP224K1_ENABLED
#run_test_psa_force_curve "secp224k1"
requires_config_enabled MBEDTLS_ECP_DP_SECP192R1_ENABLED
run_test_psa_force_curve "secp192r1"
requires_config_enabled MBEDTLS_ECP_DP_SECP192K1_ENABLED
run_test_psa_force_curve "secp192k1"
