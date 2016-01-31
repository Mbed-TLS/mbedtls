/**
 * \file gf128mul.h
 *
 * \brief Fast multiplication in GF(128)
 *
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
#ifndef MBEDTLS_GF128MUL_H
#define MBEDTLS_GF128MUL_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          Big-Endian definition for 128 bits elements
 */
typedef unsigned char mbedtls_be128[16];

/**
 * \brief          Multiplication in GF(128):
 *                 r = x times x^4 times x^8 in GF(2^128)
 *
 * \param x        the 128-bits number you want to multiply
 * \param r        result
 */
void mbedtls_gf128mul_x_ble(mbedtls_be128 r, const mbedtls_be128 x);



#endif /* gf128mul.h */