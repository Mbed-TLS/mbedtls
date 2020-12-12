#include <string.h>
#include <stdio.h>
#include "mbedtls/md.h"

#define mbedtls_printf     printf

int main(void)
{
    int ret;
    unsigned char secret[] = "a secret";
    unsigned char buffer[] = "some data to hash";
    unsigned char digest[32];
    mbedtls_md_context_t sha_ctx;

    mbedtls_md_init(&sha_ctx);
    memset(digest, 0x00, sizeof(digest));

    ret = mbedtls_md_setup(&sha_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
    if (ret != 0)
    {
        mbedtls_printf("  ! mbedtls_md_setup() returned -0x%04x\n", -ret);
        goto exit;
    }

    mbedtls_md_hmac_starts(&sha_ctx, secret, sizeof(secret) - 1);
    mbedtls_md_hmac_update(&sha_ctx, buffer, sizeof(buffer) - 1);
    mbedtls_md_hmac_finish(&sha_ctx, digest );

    mbedtls_printf("HMAC: ");
    for (int i = 0; i < sizeof(digest); i++)
        mbedtls_printf("%02X", digest[i]);
    mbedtls_printf("\n");

exit:
    mbedtls_md_free( &sha_ctx );

    return ret;
}

