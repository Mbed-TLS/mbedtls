Introduce a level of indirection and versioning in the config files
-------------------------------------------------------------------

`config.h` was split into `build_info.h` and `mbedtls_config.h`.
`build_info.h` is intended to be included from C code directly, while
`mbedtls_config.h` is intended to be edited by end users whishing to
change the build configuration, and should generally only be included from
`build_info.h`. This is because all the preprocessor logic has been moved
into `build_info.h`, including the handling of the `MBEDTLS_CONFIG_FILE`
macro.

Mandatory version symbols were introduced for `MBEDTLS_CONFIG_FILE` and
`MBEDTLS_USER_CONFIG_FILE`, `MBEDTLS_CONFIG_VERSION` and
`MBEDTLS_USER_CONFIG_VERSION` respectively. Both config files should include
a definiton of their respective version symbol, with a value of `1` to be
considered valid.
