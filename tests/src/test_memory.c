/**
 * \file memory.c
 *
 * \brief   Helper functions related to testing memory management.
 */

/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include <test/helpers.h>
#include <test/macros.h>
#include <test/memory.h>

#if defined(MBEDTLS_TEST_HAVE_ASAN)
#include <sanitizer/asan_interface.h>
#include <stdint.h>
#endif

#if defined(MBEDTLS_TEST_HAVE_ASAN)
void mbedtls_test_memory_poison(const unsigned char *ptr, size_t size)
{
    if (size == 0) {
        return;
    }
    __asan_poison_memory_region(ptr, size);
}

void mbedtls_test_memory_unpoison(const unsigned char *ptr, size_t size)
{
    if (size == 0) {
        return;
    }
    __asan_unpoison_memory_region(ptr, size);
}
#endif /* Asan */
