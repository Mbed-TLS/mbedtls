#include <stdint.h>
#include <stdlib.h>
#include "mbedtls/pk.h"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
#ifdef MBEDTLS_PK_PARSE_C
    int ret;
    mbedtls_pk_context pk;

    mbedtls_pk_init( &pk );
    ret = mbedtls_pk_parse_public_key( &pk, Data, Size );
    if (ret == 0) {
#if defined(MBEDTLS_RSA_C)
        if( mbedtls_pk_get_type( &pk ) == MBEDTLS_PK_RSA )
        {
            mbedtls_mpi N, P, Q, D, E, DP, DQ, QP;
            mbedtls_rsa_context *rsa;

            mbedtls_mpi_init( &N ); mbedtls_mpi_init( &P ); mbedtls_mpi_init( &Q );
            mbedtls_mpi_init( &D ); mbedtls_mpi_init( &E ); mbedtls_mpi_init( &DP );
            mbedtls_mpi_init( &DQ ); mbedtls_mpi_init( &QP );

            rsa = mbedtls_pk_rsa( pk );
            if ( mbedtls_rsa_export( rsa, &N, &P, &Q, &D, &E ) != 0 ) {
                abort();
            }
            if ( mbedtls_rsa_export_crt( rsa, &DP, &DQ, &QP ) != MBEDTLS_ERR_RSA_BAD_INPUT_DATA ) {
                abort();
            }

            mbedtls_mpi_free( &N ); mbedtls_mpi_free( &P ); mbedtls_mpi_free( &Q );
            mbedtls_mpi_free( &D ); mbedtls_mpi_free( &E ); mbedtls_mpi_free( &DP );
            mbedtls_mpi_free( &DQ ); mbedtls_mpi_free( &QP );

        }
        else
#endif
#if defined(MBEDTLS_ECP_C)
        if( mbedtls_pk_get_type( &pk ) == MBEDTLS_PK_ECKEY )
        {
            mbedtls_ecp_keypair *ecp;

            ecp = mbedtls_pk_ec( pk );
            //dummy use of value
            if (ecp) {
                ret = 0;
            }
        }
        else
#endif
        {
            ret = 0;
        }
    }
    mbedtls_pk_free( &pk );
#else
    (void) Data;
    (void) Size;
#endif //MBEDTLS_PK_PARSE_C

    return 0;
}
