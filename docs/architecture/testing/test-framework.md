# Mbed TLS test framework

This document is an overview of the Mbed TLS test framework and test tools.

This document is incomplete. You can help by expanding it.

## Running tests

### Outcome file

#### Generating an outcome file

Unit tests and `ssl-opt.sh` record the outcome of each test case in a **test outcome file**. This feature is enabled if the environment variable `MBEDTLS_TEST_OUTCOME_FILE` is set. Set it to the path of the desired file.

If you run `all.sh --outcome-file test-outcome.csv`, this collects the outcome of all the test cases in `test-outcome.csv`.

#### Outcome file format

The outcome file is in a CSV format using `;` (semicolon) as the delimiter and no quoting. This means that fields may not contain newlines or semicolons. There is no title line.

The outcome file has 6 fields:

* **Platform**: a description of the platform, e.g. `Linux-x86_64` or `Linux-x86_64-gcc7-msan`.
* **Configuration**: a unique description of the configuration (`config.h`).
* **Test suite**: `test_suite_xxx` or `ssl-opt`.
* **Test case**: the description of the test case.
* **Result**: one of `PASS`, `SKIP` or `FAIL`.
* **Cause**: more information explaining the result.
