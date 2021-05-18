Remove the option to build the library without any entropy sources
------------------------------------------------------------------

This does not affect users who use the default `config.h`, as this option was
already off by default.

If you were using the `MBEDTLS_TEST_NULL_ENTROPY` option, you can either use
`MBEDTLS_ENTROPY_NV_SEED` or create a fake entropy function.

