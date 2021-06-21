Introduce a level of indirection and versioning in the config files
-------------------------------------------------------------------

`config.h` was split into `build_info.h` and `mbedtls_config.h`.
`build_info.h` is intended to be included from C code directly, while
`mbedtls_config.h` is intended to be edited by end users wishing to
change the build configuration, and should generally only be included from
`build_info.h`. This is because all the preprocessor logic has been moved
into `build_info.h`, including the handling of the `MBEDTLS_CONFIG_FILE`
macro.

Config file symbols `MBEDTLS_CONFIG_VERSION` and `MBEDTLS_USER_CONFIG_VERSION`
were introduced for use in `MBEDTLS_CONFIG_FILE` and
`MBEDTLS_USER_CONFIG_FILE` respectively.
Defining them to a particular value will ensure that mbedtls interprets
the config file in a way that's compatible with the config file format
indicated by the value.
The config file versions are based on the value of `MBEDTLS_VERSION_NUMBER`
of the mbedtls version that first introduced that config file format.
The only value currently supported is `0x03000000`.
