/**
 * \file mbedtls_platform_requirements.h
 *
 * \brief Declare macros that tell system headers what we expect of them.
 *
 * This file must be included before any system header, and so in particular
 * before build_info.h (which includes the user config, which may include
 * system headers).
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef MBEDTLS_MBEDTLS_PLATFORM_REQUIREMENTS_H
#define MBEDTLS_MBEDTLS_PLATFORM_REQUIREMENTS_H

/* On Mingw-w64, force the use of a C99-compliant printf() and friends.
 * This is necessary on older versions of Mingw and/or Windows runtimes
 * where snprintf does not always zero-terminate the buffer, and does
 * not support formats such as "%zu" for size_t and "%lld" for long long.
 *
 * Defining __USE_MINGW_ANSI_STDIO=0 may work and provide a small code size
 * and performance benefit for some combinations of older Mingw and Windows
 * versions. Do this at your own risk and make sure that least
 * test_suite_debug passes.
 */
#if !defined(__USE_MINGW_ANSI_STDIO)
#define __USE_MINGW_ANSI_STDIO 1
#endif

#endif /* MBEDTLS_MBEDTLS_PLATFORM_REQUIREMENTS_H */
