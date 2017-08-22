/**
 * \file newhope.h
 * \brief NewHope
 */
#ifndef MBEDTLS_NEWHOPE_H
#define MBEDTLS_NEWHOPE_H

#include "stdint.h"
#include "stddef.h"
#include "platform.h"

#include "mbedtls/rlwe.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * NEWHOPE error codes
 */
#define MBEDTLS_ERR_NEWHOPE_BAD_INPUT_DATA                    -0x5081  /**< Bad input parameters to function. */
#define MBEDTLS_ERR_NEWHOPE_FEATURE_UNAVAILABLE               -0x5082  /**< New Hope key exchange is not available. */
#define MBEDTLS_ERR_NEWHOPE_FAILED_TO_GENERATE_RANDOM         -0x5083  /**< Unable to generate sufficient random bytes. */
#define MBEDTLS_ERR_NEWHOPE_BUFFER_TOO_SMALL                  -0x5000  /**< The buffer is too small to write to. */

#define MBEDTLS_NEWHOPE_POLY_BYTES 1792
#define MBEDTLS_NEWHOPE_SEEDBYTES 32
#define MBEDTLS_NEWHOPE_RECBYTES 256
#define MBEDTLS_NEWHOPE_SENDABYTES (MBEDTLS_NEWHOPE_POLY_BYTES + MBEDTLS_NEWHOPE_SEEDBYTES)
#define MBEDTLS_NEWHOPE_SENDBBYTES (MBEDTLS_NEWHOPE_POLY_BYTES + MBEDTLS_NEWHOPE_RECBYTES)

typedef enum
{
    MBEDTLS_NEWHOPE_DP_12289_1024_16 = 0, /*!< Newhope suggested parameters */
    MBEDTLS_NEWHOPE_DP_NONE
} mbedtls_newhope_parameter_set_id;

/**
 * Parameter set information for use by other modules
 */
typedef struct
{
    mbedtls_newhope_parameter_set_id parameter_set_id;    /*!< Internal identifier        */
    uint16_t m_Modulus;                                           /*!< Modulus */
    uint16_t m_PolynomialDegree;                                           /*!< Dimension  */
    uint16_t m_NoiseParameter;                             /*!< Noise distribution parameter         */
    const char *name;                                     /*!< Human-friendly name        */
} mbedtls_newhope_info;

/**
 * \brief           NEWHOPE context structure
 */
typedef struct
{
    mbedtls_newhope_info parameter_set;
    mbedtls_rlwe_polynomial_1024 m_PublicPolynomialFromServer;
    unsigned char m_PublicValueFromClient[MBEDTLS_NEWHOPE_SENDBBYTES];
    mbedtls_rlwe_polynomial_1024 m_V_vector;
    mbedtls_rlwe_polynomial_1024 m_SecretVector;
    mbedtls_rlwe_polynomial_1024 m_R_vector;
    unsigned char m_PublicSeedFromServer[MBEDTLS_NEWHOPE_SEEDBYTES];
    unsigned char m_SharedKeyInput[32];
}
mbedtls_newhope_context;

/**
 * \brief           Initialize context
 *
 * \param ctx       Context to initialize
 */
void mbedtls_newhope_init( mbedtls_newhope_context *ctx );

/**
 * \brief           Generate a server-side public value
 *
 * \param ctx       newhope context
 * \param olen      number of chars written
 * \param buf       destination buffer
 * \param blen      length of buffer
 *
 * \return          0 if successful, or an MBEDTLS_ERR_NEWHOPE_XXX error code
 */
int mbedtls_newhope_make_params_server( mbedtls_newhope_context *ctx, size_t *olen,
                      unsigned char **buf, size_t blen);

/**
 * \brief           Generate a client-side public value (after receipt of value from serverO
 *
 * \param ctx       newhope context
 * \param olen      number of chars written
 * \param buf       destination buffer
 * \param blen      length of buffer
 *
 * \return          0 if successful, or an MBEDTLS_ERR_NEWHOPE_XXX error code
 */
int mbedtls_newhope_make_params_client( mbedtls_newhope_context *ctx, size_t *olen,
                                        unsigned char *buf,
                                        size_t blen);

/**
 * \brief           Parse parameters and public value from server
 *
 * \param ctx       NEWHOPE context
 * \param buf       pointer to start of input buffer
 * \param end       one past end of buffer
 *
 * \return          0 if successful, or an MBEDTLS_ERR_NEWHOPE_XXX error code
 */
int mbedtls_newhope_read_parameters_and_public_value_from_server(mbedtls_newhope_context *ctx,
                                                                 const unsigned char **buf,
                                                                 const unsigned char *end);

/**
 * \brief                   Parse a public value from a newhope client
 *
 * \param ctx               newhope context
 * \param buf               start of input buffer
 * \param blen              length of input buffer
 * \param aPmsBuffer        output buffer
 * \param aPmsBufferLength  number of bytes written to output
 *
 * \return                  0 if successful, or an MBEDTLS_ERR_NEWHOPE_XXX error code
 */
int mbedtls_newhope_read_public_from_client(mbedtls_newhope_context *ctx,
                                            const unsigned char *buf,
                                            size_t blen,
                                            unsigned char *aPmsBuffer,
                                            size_t *aPmsBufferLength);

/**
 * \brief           Derive and export the shared secret.
 *                  (Last function used by both TLS client en servers.)
 *
 * \param aContext       newhope context
 * \param aFirstPoly      First polynomial for computation
 * \param aSecondPoly     Second polynomial for computation
 * \param aBuf            output buffer
 * \param aPmsLen         number of bytes written to output
 *
 * \return          0 if successful, or an MBEDTLS_ERR_NEWHOPE_XXX error code
 */
int mbedtls_newhope_calc_secret( mbedtls_newhope_context *aContext,
                                 const mbedtls_rlwe_polynomial_1024 * aFirstPoly,
                                 const mbedtls_rlwe_polynomial_1024 * aSecondPoly,
                                 unsigned char * aBuf,
                                 size_t * aPmsLen);

/**
 * \brief           Generates a public server value and writes to buffer
 *
 * \param ctx       newhope context
 * \param buf       output buffer
 * \param aBufferCapacity buffer capacity
 *
 * \return          0 if successful, or an MBEDTLS_ERR_NEWHOPE_XXX error code
 */
int mbedtls_newhope_gen_public_server(mbedtls_newhope_context * ctx, unsigned char **buf, size_t aBufferCapacity);

/**
 * \brief           Generates a public server value and writes to buffer
 *
 * \param ctx       newhope context
 * \param olen      bytes written
 * \param buf       output buffer
 * \param aBufferCapacity buffer capacity
 *
 * \return          0 if successful, or an MBEDTLS_ERR_NEWHOPE_XXX error code
 */
int mbedtls_newhope_gen_public_client(mbedtls_newhope_context * ctx, size_t *olen, unsigned char **buf, size_t aBufferCapacity);

/**
 * \brief           Parse and interpret public value from server
 *
 * \param aContext       newhope context
 * \param p         input buffer pointer
 * \param end       input buffer segment end
 *
 * \return          0 if successful, or an MBEDTLS_ERR_NEWHOPE_XXX error code
 */
int mbedtls_newhope_parse_public_value_from_server(mbedtls_newhope_context *aContext, unsigned char **p, unsigned char *end);

/**
 * \brief           Generate server-side private and public values
 *
 * \param ctx       newhope context
 * \param send      output pointer for public value
 */
void mbedtls_newhope_keygen_server(mbedtls_newhope_context *ctx, unsigned char *send);

/**
 * \brief           Generate server-side shared value after receipt of public value from client
 *
 * \param ctx       newhope context
 * \param buf       input buffer from cient
 * \param aBufferLength       length of input buffer from cient
 * \param aPmsBuffer          output buffer
 * \param aPmsBufferLength    number of bytes written to output
 *
 * \return          0 if successful, or an MBEDTLS_ERR_NEWHOPE_XXX error code
 */
int mbedtls_newhope_create_server_shared_value_n1024(mbedtls_newhope_context *ctx,
                                                     const unsigned char * const buf,
                                                     const size_t aBufferLength,
                                                     unsigned char *aPmsBuffer,
                                                     size_t *aPmsBufferLength);
/**
 * \brief           Populate buffer with pseudo-random bytes
 *
 * \param x         Buffer to populate
 * \param xlen      Number of bytes to populate
 *
 * \return          0 if successful, or an MBEDTLS_ERR_NEWHOPE_XXX error code
 */
int mbedtls_newhope_randombytes(unsigned char *x, unsigned long long xlen);

/**
 * \brief           Generate a uniformly-random rlwe polynomial
 *
 * \param a         Polynomial to generate
 * \param seed      Seed for generation
 * \param aModulus  Ring integer modulus
 */
void mbedtls_newhope_generate_random_ring_polynomial_n1024(mbedtls_rlwe_polynomial_1024 *a, const unsigned char *seed, const uint16_t aModulus);

/**
 * \brief           Encode a rlwe polynomial and seed into a buffer
 *
 * \param r         Buffer to populate
 * \param pk        RLWE polynomial
 * \param seed      Seed to append to buffer
 * \param aModulus  Ring integer modulus
 */
void mbedtls_newhope_encode_a(unsigned char *r, const mbedtls_rlwe_polynomial_1024 *pk, const unsigned char *seed, const uint16_t aModulus);

/**
 * \brief           Decode public a value into polynomial and seed
 *
 * \param pk        Polynomial to populate
 * \param seed      Seed to populate
 * \param r         Buffer to extract from
 */
void mbedtls_newhope_decode_a(mbedtls_rlwe_polynomial_1024 *pk, unsigned char *seed, const unsigned char *r);

/**
 * \brief           Convert a RWLE polynomial to byte representation (14 packed bits per coefficient)
 *
 * \param r         Byte buffer to populate
 * \param p         Input polynomial
 * \param aModulus  Ring integer modulus
 */
void mbedtls_newhope_poly_to_bytes_n1024(unsigned char *r, const mbedtls_rlwe_polynomial_1024 *p, const uint16_t aModulus);

/**
 * \brief           Convert a byte buffer into RLWE polynomial (14 packed bits per coefficient)
 *
 * \param r         polynomial to populate
 * \param a         Input byte buffer
 */
void mbedtls_newhope_poly_frombytes_n1024(mbedtls_rlwe_polynomial_1024 *r, const unsigned char *a);

/**
 * \brief           Encode the client public value
 *
 * \param r         Byte buffer to populate
 * \param b         Input polynomial 0
 * \param c         Input polynomial 1
 * \param aModulus  Ring integer modulus
 */
void mbedtls_newhope_encode_b_n1024(unsigned char *r, const mbedtls_rlwe_polynomial_1024 *b, const mbedtls_rlwe_polynomial_1024 *c, const uint16_t aModulus);

/**
 * \brief           Generate a recovery hint to allow server to recover shared value
 *
 * \param c         Polynomial to be populated as hint to server
 * \param v         Input polynomial
 * \param aModulus Ring integer modulus
 */
void mbedtls_newhope_generate_recovery_hint_polynomial(mbedtls_rlwe_polynomial_1024 *c, const mbedtls_rlwe_polynomial_1024 *v,
                                                       const uint16_t aModulus);


/**
 * \brief           Recovery helper function f
 *
 * \param v0        Pointer to temporary int32_t for holding round(x/(2*modulus))
 * \param v1        Pointer to temporary int32_t for holding ((x/modulus - 1) mod 2) + ((x/modulus - 1) >> 1)
 * \param x         Random-modified coefficient
 * \param aModulus  RLWE modulus
 *
 * \return          int32_t
 */
int32_t mbedtls_newhope_helprec_helper_function_f(int32_t *v0, int32_t *v1, const uint32_t x, const uint16_t aModulus);

/**
 * \brief           Recovery helper function g
 *
 * \param x         Extracted value (from polynomial)
 * \param aModulus  RLWE modulus
 *
 * \return          int32_t
 */
int32_t mbedtls_newhope_helprec_helper_function_g(int32_t x, const uint16_t aModulus);

/**
 * \brief           Recovery LD decode function
 *
 * \param xi0       Extracted value 1 (for recovery of single bit from 4 transmitted coefficients)
 * \param xi1       Extracted value 2 (for recovery of single bit from 4 transmitted coefficients)
 * \param xi2       Extracted value 3 (for recovery of single bit from 4 transmitted coefficients)
 * \param xi3       Extracted value 4 (for recovery of single bit from 4 transmitted coefficients)
 * \param aModulus  RLWE modulus
 *
 * \return          int16_t
 */
int16_t mbedtls_newhope_ldd_encode(int32_t xi0, int32_t xi1, int32_t xi2, int32_t xi3, const uint16_t aModulus);


/**
 * \brief           Recover the shared value following exchange
 *
 * \param key       Shared value buffer
 * \param v         Input polynomial 0
 * \param c         Input polynomial 1
 * \param aModulus Ring integer modulus
 */
void mbedtls_newhope_recover_shared_value(unsigned char *key,
                                          const mbedtls_rlwe_polynomial_1024 *v,
                                          const mbedtls_rlwe_polynomial_1024 *c,
                                          const uint16_t aModulus);



/**
 * \brief           Server-side function: recover the public value from the client
 *
 * \param b         Output polynomial 0
 * \param c         Output polynomial 1
 * \param r         Input byte buffer from client
 */
void mbedtls_newhope_decode_b_n1024(mbedtls_rlwe_polynomial_1024 *b, mbedtls_rlwe_polynomial_1024 *c, const unsigned char *r);

/**
 * \brief           Load parameters from a parameter set ID
 *
 * \param aParameterInfo       Parameter set to fill
 * \param aParameterSetId      Parameter set identifier

 *
 * \return          0 if successful, or an MBEDTLS_ERR_NEWHOPE_XXX error code
 */
int mbedtls_newhope_load_parameters_from_parameter_set_id( mbedtls_newhope_info * aParameterInfo, const int aParameterSetId);

/**
 * \brief           Return a list of supported parameter sets
 *
 * \return          Pointer to head of parameter set list
 */
const mbedtls_newhope_info *mbedtls_newhope_parameters_list( void );

#ifdef __cplusplus
}
#endif

#endif /* newhope.h */
