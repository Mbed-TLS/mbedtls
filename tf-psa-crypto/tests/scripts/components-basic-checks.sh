# components-basic-checks.sh
#
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

# This file contains test components that are executed by all.sh

################################################################
#### Basic checks
################################################################

component_tf_psa_crypto_check_recursion () {
    msg "Check: recursion.pl" # < 1s
    $MBEDTLS_FRAMEWORK_ROOT_DIR/scripts/recursion.pl ${PSA_CORE_PATH}/*.c
    $MBEDTLS_FRAMEWORK_ROOT_DIR/scripts/recursion.pl ${BUILTIN_SRC_PATH}/*.c
}

component_tf_psa_crypto_check_changelog () {
    msg "Check: changelog entries" # < 1s
    rm -f ChangeLog.new
    $MBEDTLS_FRAMEWORK_ROOT_DIR/scripts/assemble_changelog.py -o ChangeLog.new
    if [ -e ChangeLog.new ]; then
        # Show the diff for information. It isn't an error if the diff is
        # non-empty.
        diff -u ChangeLog ChangeLog.new || true
        rm ChangeLog.new
    fi
}

component_tf_psa_crypto_check_test_cases () {
    msg "Check: test case descriptions" # < 1s
    if [ $QUIET -eq 1 ]; then
        opt='--quiet'
    else
        opt=''
    fi
    $MBEDTLS_FRAMEWORK_ROOT_DIR/scripts/check_test_cases.py -q $opt
    unset opt
}

component_tf_psa_crypto_check_test_dependencies () {
    msg "Check: test case dependencies: legacy vs PSA" # < 1s
    # The purpose of this component is to catch unjustified dependencies on
    # legacy feature macros (MBEDTLS_xxx) in PSA tests. Generally speaking,
    # PSA test should use PSA feature macros (PSA_WANT_xxx, more rarely
    # MBEDTLS_PSA_xxx).
    #
    # Most of the time, use of legacy MBEDTLS_xxx macros are mistakes, which
    # this component is meant to catch. However a few of them are justified,
    # mostly by the absence of a PSA equivalent, so this component includes a
    # list of expected exceptions.

    found="check-test-deps-found-$$"
    expected="check-test-deps-expected-$$"

    # Find legacy dependencies in PSA tests
    grep 'depends_on' \
        tests/suites/test_suite_psa*.data \
        tests/suites/test_suite_psa*.function |
        grep -Eo '!?MBEDTLS_[^: ]*' |
        grep -v -e MBEDTLS_PSA_ -e MBEDTLS_TEST_ |
        sort -u > $found

    # Expected ones with justification - keep in sorted order by ASCII table!
    rm -f $expected
    # No PSA equivalent - WANT_KEY_TYPE_AES means all sizes
    echo "!MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH" >> $expected
    # No PSA equivalent - used to skip decryption tests in PSA-ECB, CBC/XTS/NIST_KW/DES
    echo "!MBEDTLS_BLOCK_CIPHER_NO_DECRYPT" >> $expected
    # MBEDTLS_ASN1_WRITE_C is used by import_rsa_made_up() in test_suite_psa_crypto
    # in order to build a fake RSA key of the wanted size based on
    # PSA_VENDOR_RSA_MAX_KEY_BITS. The legacy module is only used by
    # the test code and that's probably the most convenient way of achieving
    # the test's goal.
    echo "MBEDTLS_ASN1_WRITE_C" >> $expected
    # No PSA equivalent - used in test_suite_psa_crypto to get some "known" size
    # for raw key generation.
    echo "MBEDTLS_CTR_DRBG_MAX_REQUEST" >> $expected
    # No PSA equivalent - we should probably have one in the future.
    echo "MBEDTLS_ECP_RESTARTABLE" >> $expected
    # No PSA equivalent - needed by some init tests
    echo "MBEDTLS_ENTROPY_NV_SEED" >> $expected
    # No PSA equivalent - required to run threaded tests.
    echo "MBEDTLS_THREADING_PTHREAD" >> $expected

    # Compare reality with expectation.
    # We want an exact match, to ensure the above list remains up-to-date.
    #
    # The output should be empty. When it's not:
    # - Each '+' line is a macro that was found but not expected. You want to
    # find where that macro occurs, and either replace it with PSA macros, or
    # add it to the exceptions list above with a justification.
    # - Each '-' line is a macro that was expected but not found; it means the
    # exceptions list above should be updated by removing that macro.
    diff -U0 $expected $found

    rm $found $expected
}
