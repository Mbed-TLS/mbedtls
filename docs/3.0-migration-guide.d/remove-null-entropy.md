Remove the option to build the library without any entropy sources
------------------------------------------------------------------

This does not affect users who use the default `config.h`, as this option was
already off by default.

If you were using the `MBEDTLS_TEST_NULL_ENTROPY` option and your platform
doesn't have any entropy source, you should use `MBEDTLS_ENTROPY_NV_SEED`
and make sure your device is provisioned with a strong random seed.
Alternatively, for testing purposes only, you can create and register a fake
entropy function.
