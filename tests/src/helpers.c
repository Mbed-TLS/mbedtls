/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <test/constant_flow.h>
#include <test/helpers.h>
#include <test/macros.h>
#include <test/value_names.h>
#include <limits.h>
#include <string.h>

#if defined(MBEDTLS_PSA_INJECT_ENTROPY)
#include <psa/crypto.h>
#include <test/psa_crypto_helpers.h>
#endif

/*----------------------------------------------------------------------------*/
/* Static global variables */

#if defined(MBEDTLS_PLATFORM_C)
static mbedtls_platform_context platform_ctx;
#endif

mbedtls_test_info_t mbedtls_test_info;

/*----------------------------------------------------------------------------*/
/* Helper Functions */

int mbedtls_test_platform_setup(void)
{
    int ret = 0;

#if defined(MBEDTLS_PSA_INJECT_ENTROPY)
    /* Make sure that injected entropy is present. Otherwise
     * psa_crypto_init() will fail. This is not necessary for test suites
     * that don't use PSA, but it's harmless (except for leaving a file
     * behind). */
    ret = mbedtls_test_inject_entropy_restore();
    if (ret != 0) {
        return ret;
    }
#endif

#if defined(MBEDTLS_PLATFORM_C)
    ret = mbedtls_platform_setup(&platform_ctx);
#endif /* MBEDTLS_PLATFORM_C */

    return ret;
}

void mbedtls_test_platform_teardown(void)
{
#if defined(MBEDTLS_PLATFORM_C)
    mbedtls_platform_teardown(&platform_ctx);
#endif /* MBEDTLS_PLATFORM_C */
}

int mbedtls_test_ascii2uc(const char c, unsigned char *uc)
{
    /* Assume ASCII. Don't use ctype.h isxxx() functions because some
     * embedded platforms don't have them. */
    if ((c >= '0') && (c <= '9')) {
        *uc = c - '0';
    } else if ((c >= 'a') && (c <= 'f')) {
        *uc = c - 'a' + 10;
    } else if ((c >= 'A') && (c <= 'F')) {
        *uc = c - 'A' + 10;
    } else {
        return -1;
    }

    return 0;
}

void mbedtls_test_fail(const char *test, int line_no, const char *filename)
{
    if (mbedtls_test_info.result == MBEDTLS_TEST_RESULT_FAILED) {
        /* We've already recorded the test as having failed. Don't
         * overwrite any previous information about the failure. */
        return;
    }
    mbedtls_test_info.result = MBEDTLS_TEST_RESULT_FAILED;
    mbedtls_test_info.test = test;
    mbedtls_test_info.line_no = line_no;
    mbedtls_test_info.filename = filename;
}

void mbedtls_test_skip(const char *test, int line_no, const char *filename)
{
    mbedtls_test_info.result = MBEDTLS_TEST_RESULT_SKIPPED;
    mbedtls_test_info.test = test;
    mbedtls_test_info.line_no = line_no;
    mbedtls_test_info.filename = filename;
}

void mbedtls_test_set_step(unsigned long step)
{
    mbedtls_test_info.step = step;
}

#if defined(MBEDTLS_BIGNUM_C)
unsigned mbedtls_test_case_uses_negative_0 = 0;
#endif

void mbedtls_test_info_reset(void)
{
    mbedtls_test_info.result = MBEDTLS_TEST_RESULT_SUCCESS;
    mbedtls_test_info.step = (unsigned long) (-1);
    mbedtls_test_info.test = 0;
    mbedtls_test_info.line_no = 0;
    mbedtls_test_info.filename = 0;
    memset(mbedtls_test_info.line1, 0, sizeof(mbedtls_test_info.line1));
    memset(mbedtls_test_info.line2, 0, sizeof(mbedtls_test_info.line2));
#if defined(MBEDTLS_BIGNUM_C)
    mbedtls_test_case_uses_negative_0 = 0;
#endif
}

typedef enum {
    VALUE_CATEGORY_UNKNOWN,
    VALUE_CATEGORY_error,
    VALUE_CATEGORY_psa_status_t,
} value_category_t;

static int is_identifier_char(char c)
{
    /* Assume ASCII. Don't use ctype.h isxxx() functions because some
     * embedded platforms don't have them. */
    return (c >= '0' && c <= '9') ||
           (c >= 'A' && c <= 'Z') ||
           (c >= 'a' && c <= 'z') ||
           c == '_';
}

static value_category_t guess_value_category_from_prefix(const char *code)
{
    if (!strncmp(code, "PSA_SUCCESS", 11)) {
        return VALUE_CATEGORY_psa_status_t;
    }
    if (!strncmp(code, "PSA_ERROR_", 10)) {
        return VALUE_CATEGORY_psa_status_t;
    }
    if (!strncmp(code, "MBEDTLS_ERR_", 12)) {
        return VALUE_CATEGORY_error;
    }

    char word[64];
    size_t n;
    for (n = 0; is_identifier_char(code[n]) && n < sizeof(word) - 1; n++) {
        word[n] = code[n];
    }
    if (n > 0) {
        word[n] = 0;
        if (!strcmp(word, "ret") || strstr(word, "_ret")) {
            return VALUE_CATEGORY_error;
        }
        if (!strcmp(word, "status") || strstr(word, "_status")) {
            return VALUE_CATEGORY_psa_status_t;
        }
    }

    return VALUE_CATEGORY_UNKNOWN;
}

/** Guess the category of a value based on the C expression with
 * that value.
 *
 * The category of a value is its semantic type. That is the C type if
 * there is a dedicated C type (e.g. #psa_status_t), but it can be
 * an arbitrary name (synched with `generate_value_names.py`) otherwise
 * (e.g. `error` for `MBEDTLS_ERR_xxx` values and high+low combinations
 * thereof).
 *
 * \param code      A C expression with the given value, or
 *                  a C expression of the form `V1 == V2` where V1 and
 *                  V2 are expressions with values in that category.
 *
 * \return          The guessed category, or #VALUE_CATEGORY_UNKNOWN if
 *                  the guessing heuristics failed.
 */
static value_category_t guess_value_category(const char *code)
{
    const char *p = code;
    while (*p == ' ' || *p == '(') {
        ++p;
    }
    value_category_t category = guess_value_category_from_prefix(p);
    if (category != VALUE_CATEGORY_UNKNOWN) {
        return category;
    }

    p = strstr(p, "==");
    if (p != NULL) {
        p += 2; // skip "=="
        while (*p == ' ' || *p == '(') {
            ++p;
        }
        category = guess_value_category_from_prefix(p);
        if (category != VALUE_CATEGORY_UNKNOWN) {
            return category;
        }
    }

    return VALUE_CATEGORY_UNKNOWN;
}

static const char *get_value_name(value_category_t category,
                                  unsigned long long value)
{
    /* Naively, this would be `signed_value = value`. But do it carefully to
     * avoid allowing implementation-defined behavior such as trapping on
     * overflow. */
    long long signed_value;
    if (value <= LLONG_MAX) {
        signed_value = value;
    } else if (value >= (unsigned long long) LLONG_MIN) {
        signed_value = value - ULLONG_MAX - 1;
    } else {
        /* Can't happen on architectures where signed integers are two's
         * complement with no trap representations. */
        return NULL;
    }

    switch (category) {
        case VALUE_CATEGORY_error:
            if (signed_value >= INT_MIN && signed_value <= INT_MAX) {
                return mbedtls_test_get_name_of_error((int) value);
            } else {
                return NULL;
            }
            break;
        case VALUE_CATEGORY_psa_status_t:
            if (signed_value >= -0x80000000LL && signed_value <= 0x7fffffffLL) {
                return mbedtls_test_get_name_of_psa_status_t((psa_status_t) signed_value);
            } else {
                return NULL;
            }
            break;
        default:
            return NULL;
    }
}

/** Write a symbolic description of the specified integer value.
 *
 * \param[out] buffer   Output buffer for the symbolic description, which is
 *                      a null-terminated string. The output string is
 *                      truncated to fit if needed.
 * \param size          Size available in \p buffer in bytes.
 * \param category      The category to use for the symbolic description.
 * \param value         The value to describe. Note that for signed types,
 *                      negative values are mapped to a positive range.
 *
 * \return              The length of the output written to \p buffer,
 *                      not including the terminating null byte.
 *                      This is 0 if the function did not manage to
 *                      construct a symbolic description.
 */
static size_t append_value_name(char *buffer, size_t size,
                                value_category_t category,
                                unsigned long long value)
{
    /* Try simple value names */
    const char *name = get_value_name(category, value);
    if (name != NULL) {
        return mbedtls_snprintf(buffer, size, "%s", name);
    }

    /* Do more work with some types that have composite value names. */
    if (category == VALUE_CATEGORY_error && value >= ULLONG_MAX - 0x7fff) {
        int pos = (int) (0ull - value);
        int high_value = -(pos & 0x7f80), low_value = -(pos & 0x7f);
        const char *high_name = mbedtls_test_get_name_of_error(high_value);
        const char *low_name = mbedtls_test_get_name_of_error(low_value);
        if (high_name != NULL && low_name != NULL) {
            return mbedtls_snprintf(buffer, size, "%s + %s", high_name, low_name);
            return 1;
        } else if (high_name != NULL) {
            (void) mbedtls_snprintf(buffer, size, "%s + %d", high_name, low_value);
            return 1;
        } else if (low_name != NULL) {
            (void) mbedtls_snprintf(buffer, size, "%d + %s", high_value, low_name);
            return 1;
        }
    }

    return 0;
}

/** Write a description of the specified integer value.
 *
 * This function writes the numerical value, and attempts to write
 * a symbolic description as well.
 *
 * \param[out] line     Output buffer for the description, which is a
 *                      null-terminated string. The output string is
 *                      truncated to fit if needed.
 * \param line_size     Size available in \p line in bytes.
 * \param label         A string to print before the value.
 * \param category      The category to use for the symbolic description.
 * \param value         The value to describe. Note that for signed types,
 *                      negative values are mapped to a positive range.
 */
static void record_value(char *line, size_t line_size,
                         const char *label,
                         value_category_t category,
                         unsigned long long value)
{
    size_t n;
    n = mbedtls_snprintf(line, line_size,
                         "%s = 0x%016llx = %lld",
                         label, value, (long long) value);
    if (n + 3 < line_size && category != VALUE_CATEGORY_UNKNOWN) {
        if (append_value_name(line + n + 3, line_size - n - 3,
                              category, value) != 0) {
            line[n] = ' ';
            line[n + 1] = '=';
            line[n + 2] = ' ';
        }
    }
}

int mbedtls_test_equal(const char *test, int line_no, const char *filename,
                       unsigned long long value1, unsigned long long value2)
{
    TEST_CF_PUBLIC(&value1, sizeof(value1));
    TEST_CF_PUBLIC(&value2, sizeof(value2));

    if (value1 == value2) {
        return 1;
    }

    if (mbedtls_test_info.result == MBEDTLS_TEST_RESULT_FAILED) {
        /* We've already recorded the test as having failed. Don't
         * overwrite any previous information about the failure. */
        return 0;
    }
    mbedtls_test_fail(test, line_no, filename);

    /* Display the numerical values, and try to guess a symbolic name
     * for them as well. */
    value_category_t category = guess_value_category(mbedtls_test_info.test);
    record_value(mbedtls_test_info.line1, sizeof(mbedtls_test_info.line1),
                 "lhs", category, value1);
    record_value(mbedtls_test_info.line2, sizeof(mbedtls_test_info.line2),
                 "rhs", category, value2);

    return 0;
}

int mbedtls_test_le_u(const char *test, int line_no, const char *filename,
                      unsigned long long value1, unsigned long long value2)
{
    TEST_CF_PUBLIC(&value1, sizeof(value1));
    TEST_CF_PUBLIC(&value2, sizeof(value2));

    if (value1 <= value2) {
        return 1;
    }

    if (mbedtls_test_info.result == MBEDTLS_TEST_RESULT_FAILED) {
        /* We've already recorded the test as having failed. Don't
         * overwrite any previous information about the failure. */
        return 0;
    }
    mbedtls_test_fail(test, line_no, filename);
    (void) mbedtls_snprintf(mbedtls_test_info.line1,
                            sizeof(mbedtls_test_info.line1),
                            "lhs = 0x%016llx = %llu",
                            value1, value1);
    (void) mbedtls_snprintf(mbedtls_test_info.line2,
                            sizeof(mbedtls_test_info.line2),
                            "rhs = 0x%016llx = %llu",
                            value2, value2);
    return 0;
}

int mbedtls_test_le_s(const char *test, int line_no, const char *filename,
                      long long value1, long long value2)
{
    TEST_CF_PUBLIC(&value1, sizeof(value1));
    TEST_CF_PUBLIC(&value2, sizeof(value2));

    if (value1 <= value2) {
        return 1;
    }

    if (mbedtls_test_info.result == MBEDTLS_TEST_RESULT_FAILED) {
        /* We've already recorded the test as having failed. Don't
         * overwrite any previous information about the failure. */
        return 0;
    }
    mbedtls_test_fail(test, line_no, filename);
    (void) mbedtls_snprintf(mbedtls_test_info.line1,
                            sizeof(mbedtls_test_info.line1),
                            "lhs = 0x%016llx = %lld",
                            (unsigned long long) value1, value1);
    (void) mbedtls_snprintf(mbedtls_test_info.line2,
                            sizeof(mbedtls_test_info.line2),
                            "rhs = 0x%016llx = %lld",
                            (unsigned long long) value2, value2);
    return 0;
}

int mbedtls_test_unhexify(unsigned char *obuf,
                          size_t obufmax,
                          const char *ibuf,
                          size_t *len)
{
    unsigned char uc, uc2;

    *len = strlen(ibuf);

    /* Must be even number of bytes. */
    if ((*len) & 1) {
        return -1;
    }
    *len /= 2;

    if ((*len) > obufmax) {
        return -1;
    }

    while (*ibuf != 0) {
        if (mbedtls_test_ascii2uc(*(ibuf++), &uc) != 0) {
            return -1;
        }

        if (mbedtls_test_ascii2uc(*(ibuf++), &uc2) != 0) {
            return -1;
        }

        *(obuf++) = (uc << 4) | uc2;
    }

    return 0;
}

void mbedtls_test_hexify(unsigned char *obuf,
                         const unsigned char *ibuf,
                         int len)
{
    unsigned char l, h;

    while (len != 0) {
        h = *ibuf / 16;
        l = *ibuf % 16;

        if (h < 10) {
            *obuf++ = '0' + h;
        } else {
            *obuf++ = 'a' + h - 10;
        }

        if (l < 10) {
            *obuf++ = '0' + l;
        } else {
            *obuf++ = 'a' + l - 10;
        }

        ++ibuf;
        len--;
    }
}

unsigned char *mbedtls_test_zero_alloc(size_t len)
{
    void *p;
    size_t actual_len = (len != 0) ? len : 1;

    p = mbedtls_calloc(1, actual_len);
    TEST_HELPER_ASSERT(p != NULL);

    memset(p, 0x00, actual_len);

    return p;
}

unsigned char *mbedtls_test_unhexify_alloc(const char *ibuf, size_t *olen)
{
    unsigned char *obuf;
    size_t len;

    *olen = strlen(ibuf) / 2;

    if (*olen == 0) {
        return mbedtls_test_zero_alloc(*olen);
    }

    obuf = mbedtls_calloc(1, *olen);
    TEST_HELPER_ASSERT(obuf != NULL);
    TEST_HELPER_ASSERT(mbedtls_test_unhexify(obuf, *olen, ibuf, &len) == 0);

    return obuf;
}

int mbedtls_test_hexcmp(uint8_t *a, uint8_t *b,
                        uint32_t a_len, uint32_t b_len)
{
    int ret = 0;
    uint32_t i = 0;

    if (a_len != b_len) {
        return -1;
    }

    for (i = 0; i < a_len; i++) {
        if (a[i] != b[i]) {
            ret = -1;
            break;
        }
    }
    return ret;
}

#if defined(MBEDTLS_TEST_HOOKS)
void mbedtls_test_err_add_check(int high, int low,
                                const char *file, int line)
{
    /* Error codes are always negative (a value of zero is a success) however
     * their positive opposites can be easier to understand. The following
     * examples given in comments have been made positive for ease of
     * understanding. The structure of an error code is such:
     *
     *                                                shhhhhhhhlllllll
     *
     * s = sign bit.
     * h = high level error code (includes high level module ID (bits 12..14)
     *     and module-dependent error code (bits 7..11)).
     * l = low level error code.
     */
    if (high > -0x1000 && high != 0) {
        /* high < 0001000000000000
         * No high level module ID bits are set.
         */
        mbedtls_test_fail("'high' is not a high-level error code",
                          line, file);
    } else if (high < -0x7F80) {
        /* high > 0111111110000000
         * Error code is greater than the largest allowed high level module ID.
         */
        mbedtls_test_fail("'high' error code is greater than 15 bits",
                          line, file);
    } else if ((high & 0x7F) != 0) {
        /* high & 0000000001111111
         * Error code contains low level error code bits.
         */
        mbedtls_test_fail("'high' contains a low-level error code",
                          line, file);
    } else if (low < -0x007F) {
        /* low >  0000000001111111
         * Error code contains high or module level error code bits.
         */
        mbedtls_test_fail("'low' error code is greater than 7 bits",
                          line, file);
    } else if (low > 0) {
        mbedtls_test_fail("'low' error code is greater than zero",
                          line, file);
    }
}
#endif /* MBEDTLS_TEST_HOOKS */
