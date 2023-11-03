/** \file metatest.c
 *
 *  \brief Test features of the test framework.
 */

/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#define MBEDTLS_ALLOW_PRIVATE_ACCESS

#include <mbedtls/platform.h>
#include <mbedtls/platform_util.h>
#include "test/helpers.h"
#include "test/macros.h"

#include <stdio.h>
#include <string.h>

#if defined(MBEDTLS_THREADING_C)
#include <mbedtls/threading.h>
#endif


/* This is an external variable, so the compiler doesn't know that we're never
 * changing its value.
 *
 * TODO: LTO (link-time-optimization) would defeat this.
 */
int false_but_the_compiler_does_not_know = 0;


/****************************************************************/
/* Test framework features */
/****************************************************************/

void meta_test_fail(const char *name)
{
    (void) name;
    mbedtls_test_fail("Forced test failure", __LINE__, __FILE__);
}


/****************************************************************/
/* Platform features */
/****************************************************************/

void null_pointer_dereference(const char *name)
{
    (void) name;
    volatile char *p;
    mbedtls_platform_zeroize((void *) &p, sizeof(p));
    mbedtls_printf("%p -> %u\n", p, (unsigned) *p);
}

void null_pointer_call(const char *name)
{
    (void) name;
    unsigned (*p)(void);
    mbedtls_platform_zeroize(&p, sizeof(p));
    /* The pointer representation may be truncated, but we don't care:
     * the only point of printing it is to have some use of the pointer
     * to dissuade the compiler from optimizing it away. */
    mbedtls_printf("%lx() -> %u\n", (unsigned long) (uintptr_t) p, p());
}


/****************************************************************/
/* Memory */
/****************************************************************/

void read_after_free(const char *name)
{
    (void) name;
    volatile char *p = mbedtls_calloc(1, 1);
    *p = 'a';
    mbedtls_free((void *) p);
    mbedtls_printf("%u\n", (unsigned) *p);
}

void double_free(const char *name)
{
    (void) name;
    volatile char *p = mbedtls_calloc(1, 1);
    *p = 'a';
    mbedtls_free((void *) p);
    mbedtls_free((void *) p);
}

void read_uninitialized_stack(const char *name)
{
    (void) name;
    volatile char buf[1];
    if (false_but_the_compiler_does_not_know) {
        buf[0] = '!';
    }
    if (*buf != 0) {
        mbedtls_printf("%u\n", (unsigned) *buf);
    }
}

void memory_leak(const char *name)
{
    (void) name;
    volatile char *p = mbedtls_calloc(1, 1);
    /* Hint to the compiler that calloc must not be optimized away. */
    (void) *p;
}


/****************************************************************/
/* Threading */
/****************************************************************/

void mutex_lock_not_initialized(const char *name)
{
    (void) name;
    /* Mutex usage verification is only done with pthread, not with other
     * threading implementations. See tests/src/threading_helpers.c. */
#if defined(MBEDTLS_THREADING_PTHREAD)
    mbedtls_threading_mutex_t mutex;
    memset(&mutex, 0, sizeof(mutex));
    TEST_ASSERT(mbedtls_mutex_lock(&mutex) == 0);
exit:
    ;
#endif
}

void mutex_unlock_not_initialized(const char *name)
{
    (void) name;
    /* Mutex usage verification is only done with pthread, not with other
     * threading implementations. See tests/src/threading_helpers.c. */
#if defined(MBEDTLS_THREADING_C)
    mbedtls_threading_mutex_t mutex;
    memset(&mutex, 0, sizeof(mutex));
    TEST_ASSERT(mbedtls_mutex_unlock(&mutex) == 0);
exit:
    ;
#endif
}

void mutex_free_not_initialized(const char *name)
{
    (void) name;
    /* Mutex usage verification is only done with pthread, not with other
     * threading implementations. See tests/src/threading_helpers.c. */
#if defined(MBEDTLS_THREADING_C)
    mbedtls_threading_mutex_t mutex;
    memset(&mutex, 0, sizeof(mutex));
    mbedtls_mutex_free(&mutex);
#endif
}

void mutex_double_init(const char *name)
{
    (void) name;
#if defined(MBEDTLS_THREADING_C)
    mbedtls_threading_mutex_t mutex;
    mbedtls_mutex_init(&mutex);
    mbedtls_mutex_init(&mutex);
    mbedtls_mutex_free(&mutex);
#endif
}

void mutex_double_free(const char *name)
{
    (void) name;
#if defined(MBEDTLS_THREADING_C)
    mbedtls_threading_mutex_t mutex;
    mbedtls_mutex_init(&mutex);
    mbedtls_mutex_free(&mutex);
    mbedtls_mutex_free(&mutex);
#endif
}

void mutex_leak(const char *name)
{
    (void) name;
    /* Mutex usage verification is only done with pthread, not with other
     * threading implementations. See tests/src/threading_helpers.c. */
#if defined(MBEDTLS_THREADING_PTHREAD)
    mbedtls_threading_mutex_t mutex;
    mbedtls_mutex_init(&mutex);
#endif
}


/****************************************************************/
/* Command line entry point */
/****************************************************************/

typedef struct {
    const char *name;
    const char *platform;
    void (*entry_point)(const char *name);
} metatest_t;

metatest_t metatests[] = {
    { "test_fail", "any", meta_test_fail },
    { "null_dereference", "any", null_pointer_dereference },
    { "null_call", "any", null_pointer_call },
    { "read_after_free", "asan", read_after_free },
    { "double_free", "asan", double_free },
    { "read_uninitialized_stack", "msan", read_uninitialized_stack },
    { "memory_leak", "asan", memory_leak },
    /* Mutex usage verification is only done with pthread, not with other
     * threading implementations. See tests/src/threading_helpers.c. */
    { "mutex_lock_not_initialized", "pthread", mutex_lock_not_initialized },
    { "mutex_unlock_not_initialized", "pthread", mutex_unlock_not_initialized },
    { "mutex_free_not_initialized", "pthread", mutex_free_not_initialized },
    { "mutex_double_init", "pthread", mutex_double_init },
    { "mutex_double_free", "pthread", mutex_double_free },
    { "mutex_leak", "pthread", mutex_leak },
    { NULL, NULL, NULL }
};

static void help(FILE *out, const char *argv0)
{
    mbedtls_fprintf(out, "Usage: %s list|TEST\n", argv0);
    mbedtls_fprintf(out, "Run a meta-test that should cause a test failure.\n");
    mbedtls_fprintf(out, "With 'list', list the available tests and their platform requirement.\n");
}

int main(int argc, char *argv[])
{
    const char *argv0 = argc > 0 ? argv[0] : "metatest";
    if (argc != 2) {
        help(stderr, argv0);
        mbedtls_exit(MBEDTLS_EXIT_FAILURE);
    }

    /* Support "-help", "--help", "--list", etc. */
    const char *command = argv[1];
    while (*command == '-') {
        ++command;
    }

    if (strcmp(argv[1], "help") == 0) {
        help(stdout, argv0);
        mbedtls_exit(MBEDTLS_EXIT_SUCCESS);
    }
    if (strcmp(argv[1], "list") == 0) {
        for (const metatest_t *p = metatests; p->name != NULL; p++) {
            mbedtls_printf("%s %s\n", p->name, p->platform);
        }
        mbedtls_exit(MBEDTLS_EXIT_SUCCESS);
    }

#if defined(MBEDTLS_TEST_MUTEX_USAGE)
    mbedtls_test_mutex_usage_init();
#endif

    for (const metatest_t *p = metatests; p->name != NULL; p++) {
        if (strcmp(argv[1], p->name) == 0) {
            mbedtls_printf("Running metatest %s...\n", argv[1]);
            p->entry_point(argv[1]);
#if defined(MBEDTLS_TEST_MUTEX_USAGE)
            mbedtls_test_mutex_usage_check();
#endif
            mbedtls_printf("Running metatest %s... done, result=%d\n",
                           argv[1], (int) mbedtls_test_info.result);
            mbedtls_exit(mbedtls_test_info.result == MBEDTLS_TEST_RESULT_SUCCESS ?
                         MBEDTLS_EXIT_SUCCESS :
                         MBEDTLS_EXIT_FAILURE);
        }
    }

    mbedtls_fprintf(stderr, "%s: FATAL: No such metatest: %s\n",
                    argv0, command);
    mbedtls_exit(MBEDTLS_EXIT_FAILURE);
}
