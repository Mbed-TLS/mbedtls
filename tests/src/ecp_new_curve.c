/** \file ecp_new_curve.c
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

#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#include "test/ecp_new_curve.h"

#if defined(MBEDTLS_TEST_HOOKS) && \
    defined(MBEDTLS_ECP_C) && defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)

#include "ecp_invasive.h"
#include "mbedtls/platform.h"

#define FMT_MPI \
    "    MBEDTLS_BYTES_TO_T_UINT_8(0x%02X, 0x%02X, 0x%02X, 0x%02X, 0x%02X, 0x%02X, 0x%02X, 0x%02X),\n"

static void dump_mpi(const char *name, const mbedtls_mpi *d)
{
    /* We'll read 8 bytes at a time, so leave room in case MAX_BYTES is not a
     * multiple of 8. Also set to 0 so it's safe to read past the actual size
     * of the MPI written here. */
    uint8_t buf[MBEDTLS_ECP_MAX_BYTES + 7] = { 0 };
    size_t olen;
    uint8_t *p;

    olen = mbedtls_mpi_size(d);
    mbedtls_mpi_write_binary_le(d, buf, olen);

    mbedtls_printf("static const mbedtls_mpi_uint %s[] = {\n", name);
    for (p = buf; p < buf + olen; p += 8) {
        mbedtls_printf(FMT_MPI, p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]);
    }
    mbedtls_printf("};\n");
}

static void dump_T(const char *curve_name, mbedtls_ecp_point *T, unsigned T_size)
{
    char var_name[32];

    mbedtls_printf("#if MBEDTLS_ECP_FIXED_POINT_OPTIM == 1\n");

    /* First print each point */
    for (unsigned i = 0; i < T_size; ++i) {
        mbedtls_snprintf(var_name, sizeof(var_name), "%s_T_%u_X", curve_name, i);
        dump_mpi(var_name, &T[i].X);

        mbedtls_snprintf(var_name, sizeof(var_name), "%s_T_%u_Y", curve_name, i);
        dump_mpi(var_name, &T[i].Y);
    }

    /* Then the table referring to the above points */
    mbedtls_printf("static const mbedtls_ecp_point %s_T[%u] = {\n", curve_name, T_size);
    for (unsigned i = 0; i < T_size; ++i) {
        mbedtls_printf("    ECP_POINT_INIT_XY_Z0(%s_T_%u_X, %s_T_%u_Y),\n",
                       curve_name, i, curve_name, i);
    }
    mbedtls_printf("};\n#else\n#define %s_T NULL\n#endif\n", curve_name);
}

int ecp_print_table(mbedtls_ecp_group_id grp_id)
{
    int ret;
    mbedtls_ecp_point *T = NULL;
    mbedtls_ecp_group grp;
    mbedtls_ecp_group_init(&grp);

    MBEDTLS_MPI_CHK(mbedtls_ecp_group_load(&grp, grp_id));

    /* See ecp_pick_window_size() */
    const unsigned char w = 1 + (grp.nbits >= 384 ? 5 : 4);

    /* See ecp_mul_comb() */
    const unsigned char T_size = 1U << (w - 1);
    const size_t d = (grp.nbits + w - 1) / w;

    /* Allocate and initialize the table */
    T = mbedtls_calloc(T_size, sizeof(mbedtls_ecp_point));
    if (T == NULL) {
        ret = MBEDTLS_ERR_ECP_ALLOC_FAILED;
        goto cleanup;
    }
    for (unsigned char i = 0; i < T_size; i++) {
        mbedtls_ecp_point_init(&T[i]);
    }

    /* Populate the table */
    MBEDTLS_MPI_CHK(mbedtls_ecp_precompute_comb(&grp, T, &grp.G, w, d, NULL));

    /* Print it out */
    const mbedtls_ecp_curve_info *curve_info;
    curve_info = mbedtls_ecp_curve_info_from_grp_id(grp_id);
    dump_T(curve_info->name, T, T_size);

cleanup:
    if (T != NULL) {
        for (unsigned char i = 0; i < T_size; i++) {
            mbedtls_ecp_point_free(&T[i]);
        }
        mbedtls_free(T);
    }

    mbedtls_ecp_group_free(&grp);

    return ret;
}

#endif /* MBEDTLS_TEST_HOOKS && MBEDTLS_ECP_C && MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED */
