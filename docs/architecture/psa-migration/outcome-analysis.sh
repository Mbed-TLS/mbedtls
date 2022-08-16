#!/bin/sh

# This script runs tests in various revisions and configurations and analyses
# the results in order to highlight any difference in the set of tests skipped
# in the test suites of interest.
#
# It can be used to ensure the testing criteria mentioned in strategy.md,
# end of section "Supporting builds with drivers without the software
# implementation" are met, namely:
#
# - the sets of tests skipped in the default config and the full config must be
#   the same before and after the PR that implements step 3;
# - the set of tests skipped in the driver-only build is the same as in an
#   equivalent software-based configuration, or the difference is small enough,
#   justified, and a github issue is created to track it.
#
# WARNING: this script checks out a commit other than the head of the current
# branch; it checks out the current branch again when running successfully,
# but while the script is running, or if it terminates early in error, you
# should be aware that you might be at a different commit than expected.
#
# NOTE: This is only an example/template script, you should make a copy and
# edit it to suit your needs. The part that needs editing is at the top.
#
# Also, you can comment out parts that don't need to be re-done when
# re-running this script (for example "get numbers before this PR").

# ----- BEGIN edit this -----
# The component in all.sh that builds and tests with drivers.
DRIVER_COMPONENT=test_psa_crypto_config_accel_hash_use_psa
# A similar configuration to that of the component, except without drivers,
# for comparison.
reference_config () {
    scripts/config.py set MBEDTLS_USE_PSA_CRYPTO
    scripts/config.py unset MBEDTLS_PKCS1_V21
    scripts/config.py unset MBEDTLS_X509_RSASSA_PSS_SUPPORT
    scripts/config.py unset MBEDTLS_PKCS5_C
    scripts/config.py unset MBEDTLS_PKCS12_C
    scripts/config.py unset MBEDTLS_ECDSA_DETERMINISTIC
}
# Space-separated list of test suites of interest.
SUITES="rsa pkcs1_v15 pk pkparse pkwrite"
# ----- END edit this -----

set -eu

cleanup() {
    make clean
    git checkout -- include/mbedtls/mbedtls_config.h include/psa/crypto_config.h
}

record() {
    export MBEDTLS_TEST_OUTCOME_FILE="$PWD/outcome-$1.csv"
    rm -f $MBEDTLS_TEST_OUTCOME_FILE
    make check
}

# save current HEAD
HEAD=$(git branch --show-current)

# get the numbers before this PR for default and full
cleanup
git checkout $(git merge-base HEAD development)
record "before-default"

cleanup
scripts/config.py full
record "before-full"

# get the numbers now for default and full
cleanup
git checkout $HEAD
record "after-default"

cleanup
scripts/config.py full
record "after-full"

# get the numbers now for driver-only and reference
cleanup
reference_config
record "reference"

cleanup
export MBEDTLS_TEST_OUTCOME_FILE="$PWD/outcome-drivers.csv"
tests/scripts/all.sh -k test_psa_crypto_config_accel_hash_use_psa

# analysis

compare_suite () {
    ref="outcome-$1.csv"
    new="outcome-$2.csv"
    suite="$3"

    pattern_suite=";test_suite_$suite;"
    total=$(grep -c "$pattern_suite" "$ref")
    sed_cmd="s/^.*$pattern_suite\(.*\);SKIP.*/\1/p"
    sed -n "$sed_cmd" "$ref" > skipped-ref
    sed -n "$sed_cmd" "$new" > skipped-new
    nb_ref=$(wc -l <skipped-ref)
    nb_new=$(wc -l <skipped-new)

    printf "%12s: total %3d; skipped %3d -> %3d\n" \
            $suite      $total       $nb_ref $nb_new
    diff skipped-ref skipped-new | grep '^> ' || true
    rm skipped-ref skipped-new
}

compare_builds () {
    printf "\n*** Comparing $1 -> $2 ***\n"
    for suite in $SUITES; do
        compare_suite "$1" "$2" "$suite"
    done
}

compare_builds before-default after-default
compare_builds before-full after-full
compare_builds reference drivers

