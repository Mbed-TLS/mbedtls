/**
 * \file ecp_arith_typedefs.h
 */
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

#ifndef MBEDTLS_ECP_ARITH_TYPEDEFS_H
#define MBEDTLS_ECP_ARITH_TYPEDEFS_H

#include "mbedtls/build_info.h"

#define ECP_ARITH_WRAPPER_FIXSIZE_HEAP

/*
 * Select the right header to import
 */
#if defined(ECP_ARITH_WRAPPER_FIXSIZE_HEAP)
#include "ecp_arith_wrapper_fixsize_heap_typedefs.h"
#endif /* ECP_ARITH_WRAPPER_FIXSIZE_HEAP */

#endif /* ecp_arith_typedefs.h */
