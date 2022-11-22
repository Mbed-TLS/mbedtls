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
#   This part is verified by tests/scripts/analyze_outcomes.py
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
# Space-separated list of test suites to ignore:
# if SSS is in that list, test_suite_SSS and test_suite_SSS.* are ignored.
IGNORE="md mdx shax" # accelerated
IGNORE="$IGNORE entropy hmac_drbg random" # disabled (ext. RNG)
IGNORE="$IGNORE psa_crypto_init" # needs internal RNG
IGNORE="$IGNORE hkdf" # disabled in the all.sh component tested
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


# analysis

populate_suites () {
    SUITES=''
    make generated_files >/dev/null
    data_files=$(cd tests/suites && echo *.data)
    for data in $data_files; do
        suite=${data#test_suite_}
        suite=${suite%.data}
        suite_base=${suite%%.*}
        case " $IGNORE " in
            *" $suite_base "*) :;;
            *) SUITES="$SUITES $suite";;
        esac
    done
    make neat
}

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

    printf "%36s: total %4d; skipped %4d -> %4d\n" \
            $suite      $total       $nb_ref $nb_new
    if diff skipped-ref skipped-new | grep '^> '; then
        ret=1
    else
        ret=0
    fi
    rm skipped-ref skipped-new
    return $ret
}

compare_builds () {
    printf "\n*** Comparing $1 -> $2 ***\n"
    failed=''
    for suite in $SUITES; do
        if compare_suite "$1" "$2" "$suite"; then :; else
            failed="$failed $suite"
        fi
    done
    if [ -z "$failed" ]; then
        printf "No coverage gap found.\n"
    else
        printf "Suites with less coverage:%s\n" "$failed"
    fi
}

populate_suites
compare_builds before-default after-default
compare_builds before-full after-full
