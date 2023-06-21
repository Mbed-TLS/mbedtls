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
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

/**
 * \file pem.h
 *
 * \brief PEM-specific utility functions
 */

#ifndef MBEDTLS_PEM_MISC_H
#define MBEDTLS_PEM_MISC_H

#include "mbedtls/pem.h"

#if defined(MBEDTLS_PEM_PARSE_C)
/**
 * \brief        Platform-independent implementation of strnstr()
 *
 *               Find the first occurrence of find in s, where the search is
 *               limited to the first slen characters of s.
 *
 *               Characters that appear after a '\0' character are not searched.
 *
 * \param s      String to be scanned
 * \param needle Sequence of characters to match
 * \param slen   Maximum length of string \p s to scan
 *
 * \return       Pointer to first occurence of \p needle in \p s, or NULL
 *               if not found. Returns \p s if \p needle is an empty string.
 */
char *mbedtls_pem_strnstr(const char *s, const char *needle, size_t slen);
#endif /* MBEDTLS_PEM_PARSE_C */

#endif /* pem_misc.h */
