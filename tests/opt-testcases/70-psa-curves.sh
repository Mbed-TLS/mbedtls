#!/bin/sh

# 70-psa-curves.sh
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


# Determine what calc_verify trace is to be expected, if any.
#
# calc_verify is only called for two things: to calculate the
# extended master secret, and to process client authentication.
#
# Warning: the current implementation assumes that extended_ms is not
#          disabled on the client or on the server.
#
# Inputs:
# * $1: the value of the server auth_mode parameter.
#       'required' if client authentication is expected,
#       'none' or absent if not.
# * $CONFIGS_ENABLED
#
# Outputs:
# * $maybe_calc_verify: set to a trace expected in the debug logs
set_maybe_calc_verify() {
    maybe_calc_verify=
    case $CONFIGS_ENABLED in
        *\ MBEDTLS_SSL_EXTENDED_MASTER_SECRET\ *) :;;
        *)
            case ${1-} in
                ''|none) return;;
                required) :;;
                *) echo "Bad parameter 1 to set_maybe_calc_verify: $1"; exit 1;;
            esac
    esac
    case $CONFIGS_ENABLED in
        *\ MBEDTLS_USE_PSA_CRYPTO\ *) maybe_calc_verify="PSA calc verify";;
        *) maybe_calc_verify="<= calc verify";;
    esac
}

run_test_psa() {
    requires_config_enabled MBEDTLS_USE_PSA_CRYPTO
    set_maybe_calc_verify none
    run_test    "PSA-supported ciphersuite: $1" \
                "$P_SRV debug_level=3 force_version=tls12" \
                "$P_CLI debug_level=3 force_ciphersuite=$1" \
                0 \
                -c "$maybe_calc_verify" \
                -c "calc PSA finished" \
                -s "$maybe_calc_verify" \
                -s "calc PSA finished" \
                -s "Protocol is TLSv1.2" \
                -c "Perform PSA-based ECDH computation."\
                -c "Perform PSA-based computation of digest of ServerKeyExchange" \
                -S "error" \
                -C "error"
    unset maybe_calc_verify
}

run_test_psa_force_curve() {
    requires_config_enabled MBEDTLS_USE_PSA_CRYPTO
    set_maybe_calc_verify none
    run_test    "PSA - ECDH with $1" \
                "$P_SRV debug_level=4 force_version=tls12 curves=$1" \
                "$P_CLI debug_level=4 force_ciphersuite=TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256 curves=$1" \
                0 \
                -c "$maybe_calc_verify" \
                -c "calc PSA finished" \
                -s "$maybe_calc_verify" \
                -s "calc PSA finished" \
                -s "Protocol is TLSv1.2" \
                -c "Perform PSA-based ECDH computation."\
                -c "Perform PSA-based computation of digest of ServerKeyExchange" \
                -S "error" \
                -C "error"
    unset maybe_calc_verify
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
## (https://github.com/Mbed-TLS/mbedtls/issues/3541),
## so it is disabled in PSA even when it's enabled in Mbed TLS.
## The proper dependency would be on PSA_WANT_ECC_SECP_K1_224 but
## dependencies on PSA symbols in ssl-opt.sh are not implemented yet.
#requires_config_enabled MBEDTLS_ECP_DP_SECP224K1_ENABLED
#run_test_psa_force_curve "secp224k1"
requires_config_enabled MBEDTLS_ECP_DP_SECP192R1_ENABLED
run_test_psa_force_curve "secp192r1"
requires_config_enabled MBEDTLS_ECP_DP_SECP192K1_ENABLED
run_test_psa_force_curve "secp192k1"
