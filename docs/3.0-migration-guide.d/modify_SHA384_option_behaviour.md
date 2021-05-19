Replaced MBEDTLS_SHA512_NO_SHA384 with MBEDTLS_SHA384_C
------------------------------------------------------

This does not affect users who use the default `config.h`.
MBEDTLS_SHA512_NO_SHA384 was disabled by default, now MBEDTLS_SHA384_C is
enabled by default.

If you were using a config file with MBEDTLS_SHA512_NO_SHA384 enabled,
then just remove it (don't define MBEDTLS_SHA384_C).
