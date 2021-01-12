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
 * \file common.h
 *
 * \brief Common functions and macros used by MPS
 */

#ifndef MBEDTLS_MPS_COMMON_H
#define MBEDTLS_MPS_COMMON_H

/**
 * \name SECTION:       MPS Configuration
 *
 * \{
 */

/*! This flag enables/disables assertions on the internal state of MPS.
 *
 *  Assertions are sanity checks that should never trigger when MPS
 *  is used within the bounds of its API and preconditions.
 *
 *  Enabling this increases security by limiting the scope of
 *  potential bugs, but comes at the cost of increased code size.
 *
 *  Note: So far, there is no guiding principle as to what
 *  expected conditions merit an assertion, and which don't.
 *
 *  Comment this to disable assertions.
 */
#define MBEDTLS_MPS_ENABLE_ASSERTIONS

/*! This flag controls whether tracing for MPS should be enabled. */
#define MBEDTLS_MPS_TRACE

/* \} name SECTION: MPS Configuration */

#endif /* MBEDTLS_MPS_COMMON_H */
