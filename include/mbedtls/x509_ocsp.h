/**
 * \file x509_ocsp.h
 *
 * \brief OCSP generic defines and structures
 *
 *  Copyright (C) 2017, ARM Limited, All Rights Reserved
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
#ifndef MBEDTLS_X509_OCSP_H
#define MBEDTLS_X509_OCSP_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "x509.h"
#include "x509_crt.h"
#include "md.h"
#include "pk.h"

#include <stdint.h>

typedef struct mbedtls_x509_ocsp_response {
} mbedtls_x509_ocsp_response;

int mbedtls_x509_ocsp_response_info( char *buf, size_t size,
                                     const char *prefix,
                                     const mbedtls_x509_ocsp_response *resp );

int mbedtls_x509_ocsp_parse_response_file( mbedtls_x509_ocsp_response *resp,
                                           const char *path );

int mbedtls_x509_ocsp_parse_response( mbedtls_x509_ocsp_response *resp,
                                      unsigned char *buf, size_t buflen );

#endif /* !MBEDTLS_X509_OCSP_H */
