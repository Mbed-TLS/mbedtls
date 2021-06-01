Change MBEDTLS_ECP_FIXED_POINT_OPTIM behaviour
------------------------------------------------------

The option MBEDTLS_ECP_FIXED_POINT_OPTIM now use more ROM and does not increase
peak RAM usage anymore.

If you are limited by ROM space, you can define MBEDTLS_ECP_FIXED_POINT_OPTIM
to `0` in your config file. This will save about 50 KiB ROM space.
