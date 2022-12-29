#!/bin/sh

# This script runs tests before and after a PR and analyzes the results in
# order to highlight any difference in the set of tests skipped.
#
# It can be used to check the first testing criterion mentioned in strategy.md,
# end of section "Supporting builds with drivers without the software
# implementation", namely: the sets of tests skipped in the default config and
# the full config must be the same before and after the PR.
#
# WARNING: this script checks out a commit other than the head of the current
# branch; it checks out the current branch again when running successfully,
# but while the script is running, or if it terminates early in error, you
# should be aware that you might be at a different commit than expected.
#
# NOTE: you can comment out parts that don't need to be re-done when
# re-running this script (for example "get numbers before this PR").

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
        SUITES="$SUITES $suite"
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
