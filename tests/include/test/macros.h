/**
 * \file macros.h
 *
 * \brief   This file contains generic macros for the purpose of testing.
 */

/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef TEST_MACROS_H
#define TEST_MACROS_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include <stdlib.h>

#include "mbedtls/platform.h"

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
#include "mbedtls/memory_buffer_alloc.h"
#endif

/**
 * \brief   This macro tests the expression passed to it as a test step or
 *          individual test in a test case.
 *
 *          It allows a library function to return a value and return an error
 *          code that can be tested.
 *
 *          When MBEDTLS_CHECK_PARAMS is enabled, calls to the parameter failure
 *          callback, MBEDTLS_PARAM_FAILED(), will be assumed to be a test
 *          failure.
 *
 *          This macro is not suitable for negative parameter validation tests,
 *          as it assumes the test step will not create an error.
 *
 *          Failing the test means:
 *          - Mark this test case as failed.
 *          - Print a message identifying the failure.
 *          - Jump to the \c exit label.
 *
 *          This macro expands to an instruction, not an expression.
 *          It may jump to the \c exit label.
 *
 * \param   TEST    The test expression to be tested.
 */
#define TEST_ASSERT(TEST)                                 \
    do {                                                    \
        if (!(TEST))                                       \
        {                                                    \
            mbedtls_test_fail( #TEST, __LINE__, __FILE__);   \
            goto exit;                                        \
        }                                                    \
    } while (0)

/** This macro asserts fails the test with given output message.
 *
 * \param   MESSAGE The message to be outputed on assertion
 */
#define TEST_FAIL(MESSAGE)                           \
    do {                                                  \
        mbedtls_test_fail(MESSAGE, __LINE__, __FILE__);   \
        goto exit;                                        \
    } while (0)

/** Evaluate two integer expressions and fail the test case if they have
 * different values.
 *
 * The two expressions should have the same signedness, otherwise the
 * comparison is not meaningful if the signed value is negative.
 *
 * \param expr1     An integral-typed expression to evaluate.
 * \param expr2     Another integral-typed expression to evaluate.
 */
#define TEST_EQUAL(expr1, expr2)                                      \
    do {                                                                \
        if (!mbedtls_test_equal( #expr1 " == " #expr2, __LINE__, __FILE__, \
                                 expr1, expr2))                      \
        goto exit;                                                  \
    } while (0)

/** Evaluate two unsigned integer expressions and fail the test case
 * if they are not in increasing order (left <= right).
 *
 * \param expr1     An integral-typed expression to evaluate.
 * \param expr2     Another integral-typed expression to evaluate.
 */
#define TEST_LE_U(expr1, expr2)                                       \
    do {                                                                \
        if (!mbedtls_test_le_u( #expr1 " <= " #expr2, __LINE__, __FILE__, \
                                expr1, expr2))                      \
        goto exit;                                                  \
    } while (0)

/** Evaluate two signed integer expressions and fail the test case
 * if they are not in increasing order (left <= right).
 *
 * \param expr1     An integral-typed expression to evaluate.
 * \param expr2     Another integral-typed expression to evaluate.
 */
#define TEST_LE_S(expr1, expr2)                                       \
    do {                                                                \
        if (!mbedtls_test_le_s( #expr1 " <= " #expr2, __LINE__, __FILE__, \
                                expr1, expr2))                      \
        goto exit;                                                  \
    } while (0)

/** Allocate memory dynamically and fail the test case if this fails.
 * The allocated memory will be filled with zeros.
 *
 * You must set \p pointer to \c NULL before calling this macro and
 * put `mbedtls_free(pointer)` in the test's cleanup code.
 *
 * If \p item_count is zero, the resulting \p pointer will be \c NULL.
 * This is usually what we want in tests since API functions are
 * supposed to accept null pointers when a buffer size is zero.
 *
 * This macro expands to an instruction, not an expression.
 * It may jump to the \c exit label.
 *
 * \param pointer    An lvalue where the address of the allocated buffer
 *                   will be stored.
 *                   This expression may be evaluated multiple times.
 * \param item_count Number of elements to allocate.
 *                   This expression may be evaluated multiple times.
 *
 */
#define TEST_CALLOC(pointer, item_count)                    \
    do {                                                    \
        TEST_ASSERT((pointer) == NULL);                     \
        if ((item_count) != 0) {                            \
            (pointer) = mbedtls_calloc((item_count),        \
                                       sizeof(*(pointer))); \
            TEST_ASSERT((pointer) != NULL);                 \
        }                                                   \
    } while (0)

/** Allocate memory dynamically and fail the test case if this fails.
 * The allocated memory will be filled with zeros.
 *
 * You must set \p pointer to \c NULL before calling this macro and
 * put `mbedtls_free(pointer)` in the test's cleanup code.
 *
 * If \p item_count is zero, the resulting \p pointer will not be \c NULL.
 *
 * This macro expands to an instruction, not an expression.
 * It may jump to the \c exit label.
 *
 * \param pointer    An lvalue where the address of the allocated buffer
 *                   will be stored.
 *                   This expression may be evaluated multiple times.
 * \param item_count Number of elements to allocate.
 *                   This expression may be evaluated multiple times.
 *
 * Note: if passing size 0, mbedtls_calloc may return NULL. In this case,
 * we reattempt to allocate with the smallest possible buffer to assure a
 * non-NULL pointer.
 */
#define TEST_CALLOC_NONNULL(pointer, item_count)            \
    do {                                                    \
        TEST_ASSERT((pointer) == NULL);                     \
        (pointer) = mbedtls_calloc((item_count),            \
                                   sizeof(*(pointer)));     \
        if (((pointer) == NULL) && ((item_count) == 0)) {   \
            (pointer) = mbedtls_calloc(1, 1);               \
        }                                                   \
        TEST_ASSERT((pointer) != NULL);                     \
    } while (0)

/* For backwards compatibility */
#define ASSERT_ALLOC(pointer, item_count) TEST_CALLOC(pointer, item_count)

/** Allocate memory dynamically. If the allocation fails, skip the test case.
 *
 * This macro behaves like #TEST_CALLOC, except that if the allocation
 * fails, it marks the test as skipped rather than failed.
 */
#define TEST_CALLOC_OR_SKIP(pointer, item_count)            \
    do {                                                    \
        TEST_ASSERT((pointer) == NULL);                     \
        if ((item_count) != 0) {                            \
            (pointer) = mbedtls_calloc((item_count),        \
                                       sizeof(*(pointer))); \
            TEST_ASSUME((pointer) != NULL);                 \
        }                                                   \
    } while (0)

/* For backwards compatibility */
#define ASSERT_ALLOC_WEAK(pointer, item_count) TEST_CALLOC_OR_SKIP(pointer, item_count)

/** Compare two buffers and fail the test case if they differ.
 *
 * This macro expands to an instruction, not an expression.
 * It may jump to the \c exit label.
 *
 * \param p1        Pointer to the start of the first buffer.
 * \param size1     Size of the first buffer in bytes.
 *                  This expression may be evaluated multiple times.
 * \param p2        Pointer to the start of the second buffer.
 * \param size2     Size of the second buffer in bytes.
 *                  This expression may be evaluated multiple times.
 */
#define TEST_MEMORY_COMPARE(p1, size1, p2, size2)              \
    do {                                                       \
        TEST_EQUAL((size1), (size2));                          \
        if ((size1) != 0) {                                    \
            TEST_ASSERT(memcmp((p1), (p2), (size1)) == 0);     \
        }                                                      \
    } while (0)

/* For backwards compatibility */
#define ASSERT_COMPARE(p1, size1, p2, size2) TEST_MEMORY_COMPARE(p1, size1, p2, size2)

/**
 * \brief   This macro tests the expression passed to it and skips the
 *          running test if it doesn't evaluate to 'true'.
 *
 * \param   TEST    The test expression to be tested.
 */
#define TEST_ASSUME(TEST)                                 \
    do {                                                    \
        if (!(TEST))                                      \
        {                                                   \
            mbedtls_test_skip( #TEST, __LINE__, __FILE__); \
            goto exit;                                      \
        }                                                   \
    } while (0)

#if defined(MBEDTLS_CHECK_PARAMS) && !defined(MBEDTLS_PARAM_FAILED_ALT)
/**
 * \brief   This macro tests the statement passed to it as a test step or
 *          individual test in a test case. The macro assumes the test will fail
 *          and will generate an error.
 *
 *          It allows a library function to return a value and tests the return
 *          code on return to confirm the given error code was returned.
 *
 *          When MBEDTLS_CHECK_PARAMS is enabled, calls to the parameter failure
 *          callback, MBEDTLS_PARAM_FAILED(), are assumed to indicate the
 *          expected failure, and the test will pass.
 *
 *          This macro is intended for negative parameter validation tests,
 *          where the failing function may return an error value or call
 *          MBEDTLS_PARAM_FAILED() to indicate the error.
 *
 * \param   PARAM_ERROR_VALUE   The expected error code.
 *
 * \param   TEST                The test expression to be tested.
 */
#define TEST_INVALID_PARAM_RET(PARAM_ERR_VALUE, TEST)                 \
    do {                                                                \
        mbedtls_test_param_failed_expect_call();                       \
        if (((TEST) != (PARAM_ERR_VALUE)) ||                      \
            (mbedtls_test_param_failed_check_expected_call() != 0)) \
        {                                                               \
            mbedtls_test_fail( #TEST, __LINE__, __FILE__);             \
            goto exit;                                                  \
        }                                                               \
        mbedtls_test_param_failed_check_expected_call();               \
    } while (0)

/**
 * \brief   This macro tests the statement passed to it as a test step or
 *          individual test in a test case. The macro assumes the test will fail
 *          and will generate an error.
 *
 *          It assumes the library function under test cannot return a value and
 *          assumes errors can only be indicated byt calls to
 *          MBEDTLS_PARAM_FAILED().
 *
 *          When MBEDTLS_CHECK_PARAMS is enabled, calls to the parameter failure
 *          callback, MBEDTLS_PARAM_FAILED(), are assumed to indicate the
 *          expected failure. If MBEDTLS_CHECK_PARAMS is not enabled, no test
 *          can be made.
 *
 *          This macro is intended for negative parameter validation tests,
 *          where the failing function can only return an error by calling
 *          MBEDTLS_PARAM_FAILED() to indicate the error.
 *
 * \param   TEST                The test expression to be tested.
 */
#define TEST_INVALID_PARAM(TEST)                                       \
    do {                                                                 \
        memcpy(jmp_tmp, mbedtls_test_param_failed_get_state_buf(),     \
               sizeof(jmp_tmp));                                     \
        if (setjmp(mbedtls_test_param_failed_get_state_buf()) == 0) \
        {                                                                \
            TEST;                                                        \
            mbedtls_test_fail( #TEST, __LINE__, __FILE__);              \
            goto exit;                                                   \
        }                                                                \
        mbedtls_test_param_failed_reset_state();                        \
    } while (0)
#endif /* MBEDTLS_CHECK_PARAMS && !MBEDTLS_PARAM_FAILED_ALT */

/**
 * \brief   This macro tests the statement passed to it as a test step or
 *          individual test in a test case. The macro assumes the test will not fail.
 *
 *          It assumes the library function under test cannot return a value and
 *          assumes errors can only be indicated by calls to
 *          MBEDTLS_PARAM_FAILED().
 *
 *          When MBEDTLS_CHECK_PARAMS is enabled, calls to the parameter failure
 *          callback, MBEDTLS_PARAM_FAILED(), are assumed to indicate the
 *          expected failure. If MBEDTLS_CHECK_PARAMS is not enabled, no test
 *          can be made.
 *
 *          This macro is intended to test that functions returning void
 *          accept all of the parameter values they're supposed to accept - eg
 *          that they don't call MBEDTLS_PARAM_FAILED() when a parameter
 *          that's allowed to be NULL happens to be NULL.
 *
 *          Note: for functions that return something other that void,
 *          checking that they accept all the parameters they're supposed to
 *          accept is best done by using TEST_ASSERT() and checking the return
 *          value as well.
 *
 *          Note: this macro is available even when #MBEDTLS_CHECK_PARAMS is
 *          disabled, as it makes sense to check that the functions accept all
 *          legal values even if this option is disabled - only in that case,
 *          the test is more about whether the function segfaults than about
 *          whether it invokes MBEDTLS_PARAM_FAILED().
 *
 * \param   TEST                The test expression to be tested.
 */
#define TEST_VALID_PARAM(TEST)                                    \
    TEST_ASSERT((TEST, 1));

#define TEST_HELPER_ASSERT(a) if (!(a))                          \
    {                                                                   \
        mbedtls_fprintf(stderr, "Assertion Failed at %s:%d - %s\n",    \
                        __FILE__, __LINE__, #a);              \
        mbedtls_exit(1);                                              \
    }

/** \def ARRAY_LENGTH
 * Return the number of elements of a static or stack array.
 *
 * \param array         A value of array (not pointer) type.
 *
 * \return The number of elements of the array.
 */
/* A correct implementation of ARRAY_LENGTH, but which silently gives
 * a nonsensical result if called with a pointer rather than an array. */
#define ARRAY_LENGTH_UNSAFE(array)            \
    (sizeof(array) / sizeof(*(array)))

#if defined(__GNUC__)
/* Test if arg and &(arg)[0] have the same type. This is true if arg is
 * an array but not if it's a pointer. */
#define IS_ARRAY_NOT_POINTER(arg)                                     \
    (!__builtin_types_compatible_p(__typeof__(arg),                \
                                   __typeof__(&(arg)[0])))
/* A compile-time constant with the value 0. If `const_expr` is not a
 * compile-time constant with a nonzero value, cause a compile-time error. */
#define STATIC_ASSERT_EXPR(const_expr)                                \
    (0 && sizeof(struct { unsigned int STATIC_ASSERT : 1 - 2 * !(const_expr); }))

/* Return the scalar value `value` (possibly promoted). This is a compile-time
 * constant if `value` is. `condition` must be a compile-time constant.
 * If `condition` is false, arrange to cause a compile-time error. */
#define STATIC_ASSERT_THEN_RETURN(condition, value)   \
    (STATIC_ASSERT_EXPR(condition) ? 0 : (value))

#define ARRAY_LENGTH(array)                                           \
    (STATIC_ASSERT_THEN_RETURN(IS_ARRAY_NOT_POINTER(array),         \
                               ARRAY_LENGTH_UNSAFE(array)))

#else
/* If we aren't sure the compiler supports our non-standard tricks,
 * fall back to the unsafe implementation. */
#define ARRAY_LENGTH(array) ARRAY_LENGTH_UNSAFE(array)
#endif

/** Return the smaller of two values.
 *
 * \param x         An integer-valued expression without side effects.
 * \param y         An integer-valued expression without side effects.
 *
 * \return The smaller of \p x and \p y.
 */
#define MIN(x, y) ((x) < (y) ? (x) : (y))

/** Return the larger of two values.
 *
 * \param x         An integer-valued expression without side effects.
 * \param y         An integer-valued expression without side effects.
 *
 * \return The larger of \p x and \p y.
 */
#define MAX(x, y) ((x) > (y) ? (x) : (y))

/*
 * 32-bit integer manipulation macros (big endian)
 */
#ifndef GET_UINT32_BE
#define GET_UINT32_BE(n, b, i)                            \
    {                                                       \
        (n) = ((uint32_t) (b)[(i)] << 24)             \
              | ((uint32_t) (b)[(i) + 1] << 16)             \
              | ((uint32_t) (b)[(i) + 2] <<  8)             \
              | ((uint32_t) (b)[(i) + 3]);            \
    }
#endif

#ifndef PUT_UINT32_BE
#define PUT_UINT32_BE(n, b, i)                            \
    {                                                       \
        (b)[(i)] = (unsigned char) ((n) >> 24);       \
        (b)[(i) + 1] = (unsigned char) ((n) >> 16);       \
        (b)[(i) + 2] = (unsigned char) ((n) >>  8);       \
        (b)[(i) + 3] = (unsigned char) ((n));       \
    }
#endif

#endif /* TEST_MACROS_H */
