#ifndef MBEDTLS_RLWE_H
#define MBEDTLS_RLWE_H

#include <stdint.h>

/*
 * RLWE error codes
 */
#define MBEDTLS_ERR_RLWE_NOISE_INCORRECT                    -0x4F81  /**< Noise parameter has bad value. */

typedef struct
{
    uint16_t coeffs[1024];
} mbedtls_rlwe_polynomial_1024;

/**
 * \brief           Add two dimension-1024 RWLE polynomials, coefficient-wise
 *
 * \param r         Result of addition
 * \param a         Operand 0
 * \param b         Operand 1
 * \param aModulus  Ring integer modulus
 */
void mbedtls_rlwe_polynomial_add_n1024(mbedtls_rlwe_polynomial_1024 *r,
                                       const mbedtls_rlwe_polynomial_1024 *a,
                                       const mbedtls_rlwe_polynomial_1024 *b,
                                       const uint16_t aModulus);

/**
 * \brief           Perform modular reduction of a mod aModulus, using the Barrett technique
 *
 * \param a       Ring element to reduce
 * \param aModulus        Modulus to reduce against
 *
 * \return        Result of reduction
 */
uint16_t mbedtls_rlwe_barrett_reduce(uint16_t a, const uint16_t aModulus);



/**
 * \brief           Carry out forward NTT on a RLWE polynomial coefficient vector
 *
 * \param poly      Vector to transform
 * \param omegas    Internal pre-computed table
 * \param aModulus    Ring integer modulus
 */
void mbedtls_rlwe_forward_number_theoretic_transform_n1024(uint16_t *poly,
                                                           const uint16_t *omegas,
                                                           const uint16_t aModulus);
/**
 * \brief           Carry out montgomery reduction
 *
 * \param a         Element to reduce
 * \param aModulus  Ring integer modulus
 *
 * \return          Result of reduction
 */
uint16_t mbedtls_rlwe_montgomery_reduce(uint32_t a,
                                        const uint16_t aModulus);

/**
 * \brief           Carry out forward NTT on a RLWE polynomial
 *
 * \param r         Polynomial to transform
 * \param aModulus  Ring integer modulus
 */
void mbedtls_rlwe_forward_number_theoretic_transform_with_premultiply_n1024(mbedtls_rlwe_polynomial_1024 *r,
                                                                            const uint16_t aModulus);

/**
 * \brief           Carry out reverse NTT on a RLWE polynomial
 *
 * \param r         Polynomial to transform
 * \param aModulus  Ring integer modulus
 */
void mbedtls_rlwe_poly_inverse_number_theoretic_transform_n1024(mbedtls_rlwe_polynomial_1024 *r,
                                                                const uint16_t aModulus);

/**
 * \brief           Multiply coefficients of a polynomial (in spectral form) with a factor vector
 *
 * \param poly      Polynomial coefficients to multiply
 * \param factors   Factor vector
 * \param aModulus  Ring integer modulus
 */
void mbedtls_rlwe_multiply_coefficients_n1024(uint16_t *poly, const uint16_t *factors,
                                              const uint16_t aModulus);

/**
 * \brief           Bit-reverse (in-place) a polynomial coefficient vector
 *
 * \param aInPolynomialCoefficients      Polynomial coefficients to bit-reverse
 */
void mbedtls_rlwe_bitrev_vector_n1024(uint16_t* aInPolynomialCoefficients);

/**
 * \brief           Carry out pointwise multiplication of two RLWE polynomials
 *
 * \param r         Result of multiplication
 * \param a         Operand 0
 * \param b         Operand 1
 * \param aModulus  Ring integer modulus
 */
void mbedtls_rlwe_polynomial_pointwise_multiplication_n1024(mbedtls_rlwe_polynomial_1024 *r,
                                                            const mbedtls_rlwe_polynomial_1024 *a,
                                                            const mbedtls_rlwe_polynomial_1024 *b,
                                                            const uint16_t aModulus);

/**
 * \brief           Generate a RLWE polynomial with coefficients from the noise distribution determined by aK
 *
 * \param r         Polynomial to generate
 * \param aModulus  Ring integer modulus
 * \param aK        Noise parameter for sampling
 *
 * \return          0 if successful, or an MBEDTLS_ERR_RLWE_XXX error code
 */
int mbedtls_rlwe_generate_noise_ring_polynomial_n1024(mbedtls_rlwe_polynomial_1024 *r,
                                                      const uint16_t aModulus,
                                                      const uint16_t aK);


#endif //MBED_TLS_RLWE_H
