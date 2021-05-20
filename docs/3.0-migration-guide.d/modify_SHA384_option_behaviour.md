Replaced MBEDTLS_SHA512_NO_SHA384 with MBEDTLS_SHA384_C
------------------------------------------------------

This does not affect users who use the default `config.h`.
MBEDTLS_SHA512_NO_SHA384 was disabled by default, now MBEDTLS_SHA384_C is
enabled by default.

If you were using a config file with both MBEDTLS_SHA512_C and
MBEDTLS_SHA512_NO_SHA384, then just remove the MBEDTLS_SHA512_NO_SHA384.
If you were using a config file with MBEDTLS_SHA512_C and without
MBEDTLS_SHA512_NO_SHA384 and you need the SHA-384 algorithm, then add
`#define MBEDTLS_SHA384_C` to your config file.
