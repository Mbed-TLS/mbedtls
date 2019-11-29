/**
 * \file export.h
 *
 * \brief Handles export macros
 */
/*
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
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

#if _MSC_VER
#define _DLL_EXPORT_FLAG __declspec(dllexport)
#define _DLL_IMPORT_FLAG __declspec(dllimport)
#elif __GNUC__ >= 4
#define _DLL_EXPORT_FLAG __dllexport__ __attribute__((visibility("default")))
#define _DLL_IMPORT_FLAG __dllimport__
#else
#define _DLL_EXPORT_FLAG
#define _DLL_IMPORT_FLAG
#endif

#ifndef MBEDTLS_EXTERN
#if defined(MAKING_SHARED_MBEDTLS) || defined(MAKING_MBEDTLS_SHARED)
#define MBEDTLS_EXTERN _DLL_EXPORT_FLAG
#define MBEDTLS_EXPORT _DLL_EXPORT_FLAG
#elif defined(USING_SHARED_MBEDTLS) || defined(USING_MBEDTLS_SHARED)
#define MBEDTLS_EXTERN _DLL_IMPORT_FLAG
#define MBEDTLS_EXPORT _DLL_IMPORT_FLAG
#else
#define MBEDTLS_EXTERN extern
#define MBEDTLS_EXPORT
#endif
#endif

#ifndef MBEDX509_EXTERN
#if defined(MAKING_SHARED_MBEDX509) || defined(MAKING_MBEDX509_SHARED)
#define MBEDX509_EXTERN _DLL_EXPORT_FLAG
#define MBEDX509_EXPORT _DLL_EXPORT_FLAG
#elif defined(USING_SHARED_MBEDTLS) || defined(USING_MBEDTLS_SHARED)
#define MBEDX509_EXTERN _DLL_IMPORT_FLAG
#define MBEDX509_EXPORT _DLL_IMPORT_FLAG
#else
#define MBEDX509_EXTERN extern
#define MBEDX509_EXPORT
#endif
#endif

#ifndef MBEDCRYPTO_EXTERN
#if defined(MAKING_SHARED_MBEDCRYPTO) || defined(MAKING_MBEDCRYPTO_SHARED)
#define MBEDCRYPTO_EXTERN _DLL_EXPORT_FLAG
#define MBEDCRYPTO_EXPORT _DLL_EXPORT_FLAG
#elif defined(USING_SHARED_MBEDTLS) || defined(USING_MBEDTLS_SHARED)
#define MBEDCRYPTO_EXTERN _DLL_IMPORT_FLAG
#define MBEDCRYPTO_EXPORT _DLL_IMPORT_FLAG
#else
#define MBEDCRYPTO_EXTERN extern
#define MBEDCRYPTO_EXPORT
#endif
#endif
