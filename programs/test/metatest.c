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
#include "test/helpers.h"

#include <stdio.h>
#include <string.h>


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
    char *p;
    memset(&p, 0, sizeof(p));
    volatile char c;
    c = *p;
    (void) c;
}

void null_pointer_call(const char *name)
{
    (void) name;
    void (*p)(void);
    memset(&p, 0, sizeof(p));
    p();
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

    for (const metatest_t *p = metatests; p->name != NULL; p++) {
        if (strcmp(argv[1], p->name) == 0) {
            mbedtls_printf("Running metatest %s...\n", argv[1]);
            p->entry_point(argv[1]);
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
