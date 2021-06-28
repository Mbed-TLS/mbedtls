Introduce a level of indirection and versioning in the config files
-------------------------------------------------------------------

`config.h` was split into `build_info.h` and `mbedtls_config.h`.

* In code, use `#include <mbedtls/build_info.h>`. Don't include `mbedtls/config.h` and don't refer to `MBEDTLS_CONFIG_FILE`.
* In build tools, edit `mbedtls_config.h`, or edit `MBEDTLS_CONFIG_FILE` as before.
* If you had a tool that parsed the library version from `include/mbedtls/version.h`, this has moved to `include/mbedtls/build_info.h`. From C code, both headers now define the `MBEDTLS_VERSION_xxx` macros.

Also, if you have a custom configuration file:

* Don't include `check_config.h` or `config_psa.h` anymore.
* Don't define `MBEDTLS_CONFIG_H` anymore.

A config file version symbol, `MBEDTLS_CONFIG_VERSION` was introduced.
Defining it to a particular value will ensure that Mbed TLS interprets
the config file in a way that's compatible with the config file format
used by the Mbed TLS release whose `MBEDTLS_VERSION_NUMBER` has the same
value.
The only value supported by Mbed TLS 3.0.0 is `0x03000000`.
