/*
 * Helper program to compute the static table used by Short
 * Weierstrass curves when MBEDTLS_ECP_FIXED_POINT_OPTIM == 1.
 * See "HOW TO ADD A NEW CURVE" in library/ecp_curve.c.
 *
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

/*
 * Note: the bulk of the code is in tests/src/ecp_new_curve.c which lives in
 * tests as it needs access to library/ecp_invasive.h which is not accessible
 * to programs. However, test headers and helpers are, hence the detour.
 */

#include "test/ecp_new_curve.h"
#include "mbedtls/platform.h"

#if !defined(MBEDTLS_TEST_HOOKS) || \
    !defined(MBEDTLS_ECP_C) || !defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)
int main(void)
{
    mbedtls_printf("MBEDLTS_TEST_HOOKS and/or MBEDTLS_ECP_C and/or "
                   "MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED not defined.\n");
    return 1;
}
#elif MBEDTLS_ECP_WINDOW_SIZE < 7
int main(void)
{
    /* Static tables can be larger than MBEDTLS_ECP_WINDOW_SIZE which is the
     * limit for dynamically computed tables. However here, we are using the
     * functions that compute dynamic tables in order to compute the contents
     * of the tables that are then going to be static. So, we need the dynamic
     * limit to be large enough.
     *
     * Ask for the maxiumum, which is 7.
     */
    mbedtls_printf("MBEDTLS_ECP_WINDOW_SIZE must have its maximal value: 7.\n");
    return 1;
}
#else
int main(int argc, char *argv[])
{
    if (argc < 2) {
        mbedtls_printf("Usage: ecp_new_curve <curve_id>\n");
        return 1;
    }

    int id = atoi(argv[1]);
    mbedtls_ecp_group_id grp_id = (mbedtls_ecp_group_id) id;

    int ret = ecp_print_table(grp_id);
    if (ret != 0) {
        mbedtls_printf("ecp_print_table() returned %d (-0x%04x)\n", ret, -ret);
        return 1;
    }

    return 0;
}
#endif /* MBEDTLS_TEST_HOOKS && MBEDTLS_ECP_C && MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED */
