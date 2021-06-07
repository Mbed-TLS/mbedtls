Change MBEDTLS_ECP_FIXED_POINT_OPTIM behaviour
------------------------------------------------------

The option `MBEDTLS_ECP_FIXED_POINT_OPTIM` now increase code size and it does
not increase peak RAM usage anymore.

If you are limited by code size, you can define `MBEDTLS_ECP_FIXED_POINT_OPTIM`
to `0` in your config file. The impact depends on the number and size of
enabled curves. For example, for P-256 the difference is 1KB; see the documentation
of this option for details.

