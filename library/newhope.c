/*
 *  NewHope
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

/*
 * References:
 *
 * https://eprint.iacr.org/2015/1092.pdf
 */

#include <string.h>
#include <mbedtls/newhope.h>
#include "mbedtls/sha256.h"
#include "mbedtls/salsa20.h"


#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"

#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_NEWHOPE_C)

#include "mbedtls/newhope.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"



static const mbedtls_newhope_info newhope_supported_parameter_sets[] =
{
    { MBEDTLS_NEWHOPE_DP_12289_1024_16, 12289, 1024, 16,    "newhope_12289_1024_16"},
    { MBEDTLS_NEWHOPE_DP_NONE,          0,     0,    0,     NULL                   },
};

const mbedtls_newhope_info *mbedtls_newhope_parameters_list( void )
{
    return( newhope_supported_parameter_sets );
}


int mbedtls_newhope_make_params_server( mbedtls_newhope_context *ctx, size_t *olen,
                      unsigned char **buf, size_t blen)
{
    int ret;

    if( NULL == ctx )
    {
        return (MBEDTLS_ERR_NEWHOPE_BAD_INPUT_DATA);
    }

    if( 0 != (ret = mbedtls_newhope_load_parameters_from_parameter_set_id(&ctx->parameter_set, MBEDTLS_NEWHOPE_DP_12289_1024_16)))
    {
        return (ret);
    }

    if( 0 != ( ret = mbedtls_newhope_gen_public_server( ctx, buf, blen ) ) )
    {
        return (ret);
    }

    *olen = MBEDTLS_NEWHOPE_SEEDBYTES + MBEDTLS_NEWHOPE_POLY_BYTES;

    return( 0 );
}



int mbedtls_newhope_make_params_client( mbedtls_newhope_context *ctx, size_t *olen,
                                        unsigned char *buf, size_t aBufferCapacity)
{
    int ret;

    if( NULL == ctx )
    {
        return (MBEDTLS_ERR_NEWHOPE_BAD_INPUT_DATA);
    }

    if( 0 != (ret = mbedtls_newhope_gen_public_client(ctx, olen, &buf, aBufferCapacity) ) )
    {
        return ret;
    }

    return( 0 );
}

int mbedtls_newhope_create_server_shared_value_n1024(mbedtls_newhope_context *ctx,
                                                     const unsigned char * const buf,
                                                     const size_t aBufferLength,
                                                     unsigned char *aPmsBuffer,
                                                     size_t *aPmsBufferLength)
{

    mbedtls_rlwe_polynomial_1024 lTempUVector;
    mbedtls_rlwe_polynomial_1024 lTempRVector;

    if(aBufferLength < (MBEDTLS_NEWHOPE_POLY_BYTES + 1024 / 4))
    {
        return(MBEDTLS_ERR_NEWHOPE_BUFFER_TOO_SMALL);
    }

    mbedtls_newhope_decode_b_n1024(&lTempUVector, &lTempRVector, buf);

    mbedtls_rlwe_polynomial_pointwise_multiplication_n1024(&ctx->m_V_vector, &ctx->m_SecretVector, &lTempUVector, ctx->parameter_set.m_Modulus);
    mbedtls_rlwe_poly_inverse_number_theoretic_transform_n1024(&ctx->m_V_vector, ctx->parameter_set.m_Modulus);

    mbedtls_newhope_calc_secret(ctx, &ctx->m_V_vector, &lTempRVector, aPmsBuffer, aPmsBufferLength);

    return( 0 );

}


void mbedtls_newhope_keygen_server(mbedtls_newhope_context *ctx, unsigned char *send)
{
    mbedtls_rlwe_polynomial_1024 lA_vector, lE_vector, lTemporary_Inner_Product, lPublicValue_b;

    unsigned char seed[MBEDTLS_NEWHOPE_SEEDBYTES];
    unsigned char noiseseed[MBEDTLS_NEWHOPE_SEEDBYTES];

    mbedtls_newhope_randombytes(seed, MBEDTLS_NEWHOPE_SEEDBYTES);

    /* Generate lA_vector random ring polynomial from the seed */
    mbedtls_newhope_generate_random_ring_polynomial_n1024(&lA_vector, seed, ctx->parameter_set.m_Modulus);

    mbedtls_newhope_randombytes(noiseseed, MBEDTLS_NEWHOPE_SEEDBYTES);

    mbedtls_rlwe_generate_noise_ring_polynomial_n1024(&ctx->m_SecretVector, ctx->parameter_set.m_Modulus, ctx->parameter_set.m_NoiseParameter);
    mbedtls_rlwe_generate_noise_ring_polynomial_n1024(&lE_vector, ctx->parameter_set.m_Modulus, ctx->parameter_set.m_NoiseParameter);

    /* Putting s and lE_vector into spectral form */
    mbedtls_rlwe_forward_number_theoretic_transform_with_premultiply_n1024(&ctx->m_SecretVector, ctx->parameter_set.m_Modulus);
    mbedtls_rlwe_forward_number_theoretic_transform_with_premultiply_n1024(&lE_vector, ctx->parameter_set.m_Modulus);
    /* m_SecretVector and lE_vector are now in spectral mbedtls_newhope_NTT form */

    /* Multiplying lA_vector and s, pointwise */
    mbedtls_rlwe_polynomial_pointwise_multiplication_n1024(&lTemporary_Inner_Product, &ctx->m_SecretVector, &lA_vector, ctx->parameter_set.m_Modulus);

    /* add together lTemporary_Inner_Product (=as) and lE_vector */
    mbedtls_rlwe_polynomial_add_n1024(&lPublicValue_b, &lE_vector, &lTemporary_Inner_Product, ctx->parameter_set.m_Modulus);

    /* Encode the public value with the seed, into the send value */
    mbedtls_newhope_encode_a(send, &lPublicValue_b, seed, ctx->parameter_set.m_Modulus);
}

int mbedtls_newhope_gen_public_client(mbedtls_newhope_context *ctx, size_t *olen, unsigned char **buf,
                                      size_t aBufferCapacity)
{

    int ret, i;

    mbedtls_rlwe_polynomial_1024 lS_prime, lE_prime, lA_vector, lE_prime_prime, lU_vector;
    unsigned char noiseseed[32];

    if(MBEDTLS_NEWHOPE_SENDBBYTES > aBufferCapacity)
    {
        return (MBEDTLS_ERR_NEWHOPE_BUFFER_TOO_SMALL);
    }

    if(0 != (ret = mbedtls_newhope_randombytes(noiseseed, 32)))
    {
        return( MBEDTLS_ERR_NEWHOPE_FAILED_TO_GENERATE_RANDOM );
    }

    mbedtls_newhope_generate_random_ring_polynomial_n1024(&lA_vector, ctx->m_PublicSeedFromServer, ctx->parameter_set.m_Modulus);

    // Generate the three noise polynomials
    mbedtls_rlwe_generate_noise_ring_polynomial_n1024(&lS_prime, ctx->parameter_set.m_Modulus, ctx->parameter_set.m_NoiseParameter);
    mbedtls_rlwe_generate_noise_ring_polynomial_n1024(&lE_prime, ctx->parameter_set.m_Modulus, ctx->parameter_set.m_NoiseParameter);
    mbedtls_rlwe_generate_noise_ring_polynomial_n1024(&lE_prime_prime, ctx->parameter_set.m_Modulus, ctx->parameter_set.m_NoiseParameter);

    // Put s' and e' into spectral form
    mbedtls_rlwe_forward_number_theoretic_transform_with_premultiply_n1024(&lS_prime, ctx->parameter_set.m_Modulus);
    mbedtls_rlwe_forward_number_theoretic_transform_with_premultiply_n1024(&lE_prime, ctx->parameter_set.m_Modulus);

    // Compute as
    mbedtls_rlwe_polynomial_pointwise_multiplication_n1024(&lU_vector, &lA_vector, &lS_prime, ctx->parameter_set.m_Modulus);

    mbedtls_rlwe_polynomial_add_n1024(&lU_vector, &lU_vector, &lE_prime, ctx->parameter_set.m_Modulus);

    mbedtls_rlwe_polynomial_pointwise_multiplication_n1024(&ctx->m_V_vector, &ctx->m_PublicPolynomialFromServer, &lS_prime, ctx->parameter_set.m_Modulus);
    mbedtls_rlwe_poly_inverse_number_theoretic_transform_n1024(&ctx->m_V_vector, ctx->parameter_set.m_Modulus);

    mbedtls_rlwe_polynomial_add_n1024(&ctx->m_V_vector, &ctx->m_V_vector, &lE_prime_prime, ctx->parameter_set.m_Modulus);

    mbedtls_newhope_generate_recovery_hint_polynomial(&ctx->m_R_vector, &ctx->m_V_vector, ctx->parameter_set.m_Modulus);


    // Send u and r back to the server
    mbedtls_newhope_encode_b_n1024(ctx->m_PublicValueFromClient, &lU_vector, &ctx->m_R_vector, ctx->parameter_set.m_Modulus);

    // Need to write senda to the buffer now
    memset(*buf, 0x00, MBEDTLS_NEWHOPE_SENDBBYTES);

    for(i = 0; i < MBEDTLS_NEWHOPE_SENDBBYTES; ++i)
    {
        (*buf)[i] = ctx->m_PublicValueFromClient[i];
    }

    *buf += MBEDTLS_NEWHOPE_SENDBBYTES;
    *olen = MBEDTLS_NEWHOPE_SENDBBYTES;

    return( 0 );
}

/* Generate public and secret values (server) */
int mbedtls_newhope_gen_public_server(mbedtls_newhope_context * ctx, unsigned char **buf, size_t aBufferCapacity)
{

    unsigned char senda[MBEDTLS_NEWHOPE_SENDABYTES];
    int i;

    if(MBEDTLS_NEWHOPE_SENDABYTES > aBufferCapacity)
    {
        return (MBEDTLS_ERR_NEWHOPE_BUFFER_TOO_SMALL);

    }
    mbedtls_newhope_keygen_server(ctx, senda);

    // Need to write senda to the buffer now

    memset(*buf, 0x00, MBEDTLS_NEWHOPE_SENDABYTES);

    for(i = 0; i < MBEDTLS_NEWHOPE_SENDABYTES; ++i)
    {
        (*buf)[i] = senda[i];
    }

    return (0);
}

/*
 * Read the ServerKeyExchange parameters
 */
int mbedtls_newhope_read_parameters_and_public_value_from_server(mbedtls_newhope_context *ctx,
                                                                 const unsigned char **buf, const unsigned char *end)
{

    // Each coefficient has 14 bits reserved, so we need to read off and un-bitpack them
    unsigned char lTemporaryUnpackingStore[MBEDTLS_NEWHOPE_POLY_BYTES + MBEDTLS_NEWHOPE_SEEDBYTES];
    int i;

    // Check the buffer window
    if((end - *buf) < (MBEDTLS_NEWHOPE_POLY_BYTES + MBEDTLS_NEWHOPE_SEEDBYTES))
    {
        // Window is too small
        return( MBEDTLS_ERR_NEWHOPE_BUFFER_TOO_SMALL );
    }

    mbedtls_newhope_load_parameters_from_parameter_set_id(&ctx->parameter_set, MBEDTLS_NEWHOPE_DP_12289_1024_16);


    memset(lTemporaryUnpackingStore, 0, MBEDTLS_NEWHOPE_POLY_BYTES + MBEDTLS_NEWHOPE_SEEDBYTES);

    for(i = 0; i < (MBEDTLS_NEWHOPE_POLY_BYTES + MBEDTLS_NEWHOPE_SEEDBYTES); ++i)
    {
        lTemporaryUnpackingStore[i] = (*buf)[i];
    }

    mbedtls_newhope_decode_a(&ctx->m_PublicPolynomialFromServer, ctx->m_PublicSeedFromServer, lTemporaryUnpackingStore);

    return( 0 );
}

int mbedtls_newhope_load_parameters_from_parameter_set_id( mbedtls_newhope_info * aParameterInfo, const int aParameterSetId)
{

    aParameterInfo->parameter_set_id = aParameterSetId;

    switch( aParameterSetId )
    {
#if defined(MBEDTLS_NEWHOPE_DP_12289_1024_16_ENABLED)
        case MBEDTLS_NEWHOPE_DP_12289_1024_16:

            aParameterInfo->m_Modulus = newhope_supported_parameter_sets[MBEDTLS_NEWHOPE_DP_12289_1024_16].m_Modulus;
            aParameterInfo->m_PolynomialDegree = newhope_supported_parameter_sets[MBEDTLS_NEWHOPE_DP_12289_1024_16].m_PolynomialDegree;
            aParameterInfo->m_NoiseParameter = newhope_supported_parameter_sets[MBEDTLS_NEWHOPE_DP_12289_1024_16].m_NoiseParameter;
            aParameterInfo->name = newhope_supported_parameter_sets[MBEDTLS_NEWHOPE_DP_12289_1024_16].name;

            return( 0 );
#endif /* MBEDTLS_NEWHOPE_DP_12289_1024_16_ENABLED */

        default:
            return( MBEDTLS_ERR_NEWHOPE_FEATURE_UNAVAILABLE );
    }
}

int mbedtls_newhope_parse_public_value_from_server(mbedtls_newhope_context *aContext,
                                                      unsigned char **p,
                                                      unsigned char *end)
{
    mbedtls_newhope_read_parameters_and_public_value_from_server(aContext, (const unsigned char **) p, end);

    *p += (MBEDTLS_NEWHOPE_POLY_BYTES + MBEDTLS_NEWHOPE_SEEDBYTES);

    return( 0 );
}

/*
 * Parse and import the client's public value
 */

int mbedtls_newhope_read_public_from_client(mbedtls_newhope_context *ctx,
                                            const unsigned char *buf,
                                            size_t blen,
                                            unsigned char *aPmsBuffer,
                                            size_t *aPmsBufferLength)
{
    int ret = 0;

    mbedtls_newhope_create_server_shared_value_n1024(ctx, buf, blen, aPmsBuffer, aPmsBufferLength);

    return( ret );
}


/*
 * Derive and export the shared secret
 */
int mbedtls_newhope_calc_secret( mbedtls_newhope_context *aContext,
                                 const mbedtls_rlwe_polynomial_1024 * aFirstPoly,
                                 const mbedtls_rlwe_polynomial_1024 * aSecondPoly,
                                 unsigned char * aBuf,
                                 size_t *aPmsLen)
{

    mbedtls_newhope_recover_shared_value(aContext->m_SharedKeyInput, aFirstPoly, aSecondPoly, aContext->parameter_set.m_Modulus);

    mbedtls_sha256(aContext->m_SharedKeyInput, 32, aContext->m_SharedKeyInput, 0);

    memcpy(aBuf, aContext->m_SharedKeyInput, 32);
    *aPmsLen = 32;

    return 0;
}

int mbedtls_newhope_randombytes(unsigned char *x, unsigned long long xlen)
{

    int ret;
    mbedtls_ctr_drbg_context lCtrDrbg;
    const char * lLocalisedAdditionalEntropy = "newhoperandom";

    mbedtls_entropy_context lEntropy;
    mbedtls_entropy_init(&lEntropy);

    mbedtls_ctr_drbg_init(&lCtrDrbg);
    ret = mbedtls_ctr_drbg_seed( &lCtrDrbg , mbedtls_entropy_func, &lEntropy,
                                 (const unsigned char *) lLocalisedAdditionalEntropy,
                                 strlen( lLocalisedAdditionalEntropy ) );
    if( 0 != ret )
    {
        return( MBEDTLS_ERR_NEWHOPE_FEATURE_UNAVAILABLE );
    }

    ret = mbedtls_ctr_drbg_random(&lCtrDrbg, x, xlen);

    if( 0 != ret )
    {
        return (MBEDTLS_ERR_NEWHOPE_FAILED_TO_GENERATE_RANDOM);

    }

    return (0);
}

void mbedtls_newhope_generate_random_ring_polynomial_n1024(mbedtls_rlwe_polynomial_1024 *aPolynomialToFill, const unsigned char *seed, const uint16_t aModulus)
{
    /* Reference implementation uses Keccak. We use Salsa20 */
    unsigned int pos = 0, lCoefficientIndex = 0;

    const unsigned int lBufferSize = 128;

    unsigned char lRandomOutputBuffer[lBufferSize];
    unsigned char lZeroInputBuffer[lBufferSize];
    unsigned char lKey[MBEDTLS_NEWHOPE_SEEDBYTES / 2];
    unsigned char lIv[MBEDTLS_NEWHOPE_SEEDBYTES / 2];

    mbedtls_salsa20_context ctx;

    memset(lZeroInputBuffer, 0, lBufferSize);


    memcpy(lKey, seed, MBEDTLS_NEWHOPE_SEEDBYTES / 2);
    memcpy(lIv, seed + MBEDTLS_NEWHOPE_SEEDBYTES / 2, MBEDTLS_NEWHOPE_SEEDBYTES / 2);

    mbedtls_salsa20_init( &ctx );
    mbedtls_salsa20_setup(&ctx, lKey, MBEDTLS_NEWHOPE_SEEDBYTES / 2);
    mbedtls_salsa20_set_iv(&ctx, lIv);
    mbedtls_salsa20_crypt(&ctx, lBufferSize, lZeroInputBuffer, lRandomOutputBuffer );

    while (lCoefficientIndex < 1024)
    {
        uint16_t lCoefficient = (lRandomOutputBuffer[pos] | ((uint16_t) lRandomOutputBuffer[pos + 1] << 8));
        if (lCoefficient < 5 * aModulus)
        {
            aPolynomialToFill->coeffs[lCoefficientIndex++] = lCoefficient;
        }
        pos += 2;
        if (pos > lBufferSize - 2)
        {
            mbedtls_salsa20_crypt(&ctx, lBufferSize, lZeroInputBuffer, lRandomOutputBuffer );
            pos = 0;
        }
    }
}

void mbedtls_newhope_encode_a(unsigned char *r, const mbedtls_rlwe_polynomial_1024 *pk, const unsigned char *seed, const uint16_t aModulus)
{
    int i;
  
    mbedtls_newhope_poly_to_bytes_n1024(r, pk, aModulus);

    for( i=0 ; i< MBEDTLS_NEWHOPE_SEEDBYTES ; i++)
    {
        r[MBEDTLS_NEWHOPE_POLY_BYTES + i] = seed[i];
    }
}

void mbedtls_newhope_encode_b_n1024(unsigned char *r, const mbedtls_rlwe_polynomial_1024 *b, const mbedtls_rlwe_polynomial_1024 *c, const uint16_t aModulus)
{
    int i;

    mbedtls_newhope_poly_to_bytes_n1024(r, b, aModulus);
    for( i = 0; i < 1024 / 4; i++ )
    {
        r[MBEDTLS_NEWHOPE_POLY_BYTES + i] =
        c->coeffs[4 * i] | (c->coeffs[4 * i + 1] << 2) | (c->coeffs[4 * i + 2] << 4) | (c->coeffs[4 * i + 3] << 6);
    }
}

void mbedtls_newhope_poly_to_bytes_n1024(unsigned char *r, const mbedtls_rlwe_polynomial_1024 *p, const uint16_t aModulus)
{

    int i;
    uint16_t lT0;
    uint16_t lT1;
    uint16_t lT2;
    uint16_t lT3;
    uint16_t  lm;

    int16_t c;

    for( i=0; i<1024/4; i++ )
    {
        lT0 = mbedtls_rlwe_barrett_reduce(p->coeffs[4 * i + 0], aModulus); //Make sure that coefficients have only 14 bits
        lT1 = mbedtls_rlwe_barrett_reduce(p->coeffs[4 * i + 1], aModulus);
        lT2 = mbedtls_rlwe_barrett_reduce(p->coeffs[4 * i + 2], aModulus);
        lT3 = mbedtls_rlwe_barrett_reduce(p->coeffs[4 * i + 3], aModulus);

        lm = lT0 - aModulus;
        c = lm;
        c >>= 15;
        lT0 = lm ^ ((lT0^lm)&c); // <Make sure that coefficients are in [0,q]

        lm = lT1 - aModulus;
        c = lm;
        c >>= 15;
        lT1 = lm ^ ((lT1^lm)&c); // <Make sure that coefficients are in [0,q]

        lm = lT2 - aModulus;
        c = lm;
        c >>= 15;
        lT2 = lm ^ ((lT2^lm)&c); // <Make sure that coefficients are in [0,q]

        lm = lT3 - aModulus;
        c = lm;
        c >>= 15;
        lT3 = lm ^ ((lT3^lm)&c); // <Make sure that coefficients are in [0,q]

        r[7*i+0] =  lT0 & 0xff;
        r[7*i+1] = (lT0 >> 8) | (lT1 << 6);
        r[7*i+2] = (lT1 >> 2);
        r[7*i+3] = (lT1 >> 10) | (lT2 << 4);
        r[7*i+4] = (lT2 >> 4);
        r[7*i+5] = (lT2 >> 12) | (lT3 << 2);
        r[7*i+6] = (lT3 >> 6);
    }
}

void mbedtls_newhope_init( mbedtls_newhope_context *ctx )
{
    memset( ctx, 0, sizeof( mbedtls_newhope_context ) );
}

void mbedtls_newhope_decode_a(mbedtls_rlwe_polynomial_1024 *pk, unsigned char *seed, const unsigned char *r)
{
    int i;
    mbedtls_newhope_poly_frombytes_n1024(pk, r);
    for( i=0; i < MBEDTLS_NEWHOPE_SEEDBYTES; i++ )
    {
        seed[i] = r[MBEDTLS_NEWHOPE_POLY_BYTES + i];
    }
}

void mbedtls_newhope_poly_frombytes_n1024(mbedtls_rlwe_polynomial_1024 *r, const unsigned char *a)
{
    int i;
    for( i = 0; i < 1024 / 4; i++ )
    {
        r->coeffs[4*i+0] =                               a[7*i+0]        | (((uint16_t)a[7*i+1] & 0x3f) << 8);
        r->coeffs[4*i+1] = (a[7*i+1] >> 6) | (((uint16_t)a[7*i+2]) << 2) | (((uint16_t)a[7*i+3] & 0x0f) << 10);
        r->coeffs[4*i+2] = (a[7*i+3] >> 4) | (((uint16_t)a[7*i+4]) << 4) | (((uint16_t)a[7*i+5] & 0x03) << 12);
        r->coeffs[4*i+3] = (a[7*i+5] >> 2) | (((uint16_t)a[7*i+6]) << 6);
    }
}





void mbedtls_newhope_generate_recovery_hint_polynomial(mbedtls_rlwe_polynomial_1024 *c, const mbedtls_rlwe_polynomial_1024 *v,
                                                       const uint16_t aModulus)
{
    int i;
    int32_t v0[4], v1[4], v_tmp[4];
    unsigned char rand[32];

    mbedtls_newhope_randombytes(rand, MBEDTLS_NEWHOPE_SEEDBYTES);

    for( i = 0; i < 256; i++ )
    {
        unsigned char rbit = (rand[i>>3] >> (i&7)) & 1;

        int32_t k  = mbedtls_newhope_helprec_helper_function_f(v0+0, v1+0, 8*v->coeffs[  0+i] + 4*rbit, aModulus);
        k += mbedtls_newhope_helprec_helper_function_f(v0+1, v1+1, 8*v->coeffs[256+i] + 4*rbit, aModulus);
        k += mbedtls_newhope_helprec_helper_function_f(v0+2, v1+2, 8*v->coeffs[512+i] + 4*rbit, aModulus);
        k += mbedtls_newhope_helprec_helper_function_f(v0+3, v1+3, 8*v->coeffs[768+i] + 4*rbit, aModulus);

        k = (2* aModulus - 1 - k) >> 31;

        v_tmp[0] = ((~k) & v0[0]) ^ (k & v1[0]);
        v_tmp[1] = ((~k) & v0[1]) ^ (k & v1[1]);
        v_tmp[2] = ((~k) & v0[2]) ^ (k & v1[2]);
        v_tmp[3] = ((~k) & v0[3]) ^ (k & v1[3]);

        c->coeffs[  0+i] = (v_tmp[0] -   v_tmp[3]) & 3;
        c->coeffs[256+i] = (v_tmp[1] -   v_tmp[3]) & 3;
        c->coeffs[512+i] = (v_tmp[2] -   v_tmp[3]) & 3;
        c->coeffs[768+i] = (   -k    + 2*v_tmp[3]) & 3;
    }
}


int32_t mbedtls_newhope_helprec_helper_function_f(int32_t *v0, int32_t *v1, const uint32_t x, const uint16_t aModulus)
{

    // Next 6 lines compute t = x/PARAM_Q;
    int32_t xit, r;
    int32_t b = x * 2730;
    int32_t t = b >> 25;
    int32_t signedModulus, signedX;
    b = x - t * 12289;
    b = 12288 - b;
    b >>= 31;
    t -= b;

    r = t & 1;
    xit = ( t >> 1 );
    *v0 = xit + r; // v0 = round(x/(2*PARAM_Q))

    t -= 1;
    r = t & 1;
    *v1 = ( t >> 1 ) + r;

    signedModulus = (int32_t) aModulus;
    signedX = (int32_t) x;
    
    return abs( signedX - (( *v0 ) * 2 * signedModulus ));
}

int32_t mbedtls_newhope_helprec_helper_function_g(int32_t x, const uint16_t aModulus)
{

    // Next 6 lines compute t = x/(4*PARAM_Q);
    int32_t b = x*2730;
    int32_t t = b >> 27;
    b = x - t*49156;
    b = 49155 - b;
    b >>= 31;
    t -= b;

    b = t & 1;
    t = (t >> 1) + b; // t = round(x/(8*PARAM_Q))

    t *= 8 * aModulus;

    return abs(t - x);
}

void mbedtls_newhope_recover_shared_value(unsigned char *key, const mbedtls_rlwe_polynomial_1024 *v, const mbedtls_rlwe_polynomial_1024 *c, const uint16_t aModulus)
{
    int i;
    int32_t tmp[4];

    memset(key, 0x00, 32);

    for( i = 0; i < 256; i++ )
    {
        tmp[0] = 16*aModulus + 8*(int32_t)v->coeffs[  0+i] - aModulus * (2*c->coeffs[  0+i]+c->coeffs[768+i]);
        tmp[1] = 16*aModulus + 8*(int32_t)v->coeffs[256+i] - aModulus * (2*c->coeffs[256+i]+c->coeffs[768+i]);
        tmp[2] = 16*aModulus + 8*(int32_t)v->coeffs[512+i] - aModulus * (2*c->coeffs[512+i]+c->coeffs[768+i]);
        tmp[3] = 16*aModulus + 8*(int32_t)v->coeffs[768+i] - aModulus * (c->coeffs[768+i]);

        key[i>>3] |= mbedtls_newhope_ldd_encode(tmp[0], tmp[1], tmp[2], tmp[3], aModulus) << (i & 7);
    }
}

int16_t mbedtls_newhope_ldd_encode(int32_t xi0, int32_t xi1, int32_t xi2, int32_t xi3, const uint16_t aModulus)
{

    int32_t t  = mbedtls_newhope_helprec_helper_function_g(xi0, aModulus);
    t += mbedtls_newhope_helprec_helper_function_g(xi1, aModulus);
    t += mbedtls_newhope_helprec_helper_function_g(xi2, aModulus);
    t += mbedtls_newhope_helprec_helper_function_g(xi3, aModulus);

    t -= 8 * aModulus;
    t >>= 31;
    return t&1;
}

void mbedtls_newhope_decode_b_n1024(mbedtls_rlwe_polynomial_1024 *b, mbedtls_rlwe_polynomial_1024 *c, const unsigned char *r)
{
    int i;
    
    mbedtls_newhope_poly_frombytes_n1024(b, r);
    for( i = 0; i < 1024/4; i++ )
    {
        c->coeffs[4*i+0] =  r[MBEDTLS_NEWHOPE_POLY_BYTES+i]       & 0x03;
        c->coeffs[4*i+1] = (r[MBEDTLS_NEWHOPE_POLY_BYTES+i] >> 2) & 0x03;
        c->coeffs[4*i+2] = (r[MBEDTLS_NEWHOPE_POLY_BYTES+i] >> 4) & 0x03;
        c->coeffs[4*i+3] = (r[MBEDTLS_NEWHOPE_POLY_BYTES+i] >> 6);
    }
}

#endif /* MBEDTLS_NEWHOPE_C */
