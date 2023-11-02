/** \file ecp_new_curve.h
 *
 * \brief Helper function to compute the static table used by Short
 * Weierstrass curves when MBEDTLS_ECP_FIXED_POINT_OPTIM == 1.
 * Used by programs/test/ecp_new_curve.c, see "HOW TO ADD A NEW CURVE"
 * in library/ecp_curves.c.
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

#ifndef ECP_NEW_CURVE_H
#define ECP_NEW_CURVE_H

#include "mbedtls/build_info.h"
#include "mbedtls/ecp.h" // needed for SHORT_WEIERSTRASS_ENABLED

#if defined(MBEDTLS_TEST_HOOKS) && \
    defined(MBEDTLS_ECP_C) && defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)

/**
 * Print the static table for this group in a format that can be copy-pasted
 * to ecp_curves.c.
 */
int ecp_print_table(mbedtls_ecp_group_id grp_id);

#endif /* MBEDTLS_TEST_HOOKS && MBEDTLS_ECP_C && MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED */

#endif /* ECP_NEW_CURVE_H */
