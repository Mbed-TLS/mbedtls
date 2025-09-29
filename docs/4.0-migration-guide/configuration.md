## Compile-time configuration

### Configuration file split

All configuration options that are relevant to TF-PSA-Crypto must now be configured in one of its configuration files, namely:

* `TF_PSA_CRYPTO_CONFIG_FILE`, if set on the preprocessor command line;
* otherwise `<psa/crypto_config.h>`;
* additionally `TF_PSA_CRYPTO_USER_CONFIG_FILE`, if set.

Configuration options that are relevant to X.509 or TLS should still be set in the Mbed TLS configuration file (`MBEDTLS_CONFIG_FILE` or `<mbedtls/mbedtls_config.h>`, plus `MBEDTLS_USER_CONFIG_FILE` if it is set). However, you can define all options in the crypto configuration, and Mbed TLS will pick them up.

Generally speaking, the options that must be configured in TF-PSA-Crypto are:

* options related to platform settings;
* options related to the choice of cryptographic mechanisms included in the build;
* options related to the inner workings of cryptographic mechanisms, such as size/memory/performance compromises;
* options related to crypto-adjacent features, such as ASN.1 and Base64.

See `include/psa/crypto_config.h` in TF-PSA-Crypto and `include/mbedtls/mbedtls_config.h` in Mbed TLS for details.

Notably, `<psa/crypto_config.h>` is no longer limited to `PSA_WANT_xxx` options.

Note that many options related to cryptography have changed; see the TF-PSA-Crypto migration guide for details.

### Split of `build_info.h` and `version.h`

The header file `<mbedtls/build_info.h>`, which includes the configuration file and provides the adjusted configuration macros, now has an similar file `<tf-psa-crypto/build_info.h>` in TF-PSA-Crypto. The Mbed TLS header includes the TF-PSA-Crypto header, so including `<mbedtls/build_info.h>` remains sufficient to obtain information about the crypto configuration.

TF-PSA-Crypto exposes its version through `<tf-psa-crypto/version.h>`, similar to `<mbedtls/version.h>` in Mbed TLS.

### Removal of `check_config.h`

The header `mbedtls/check_config.h` is no longer present. Including it from user configuration files was already obsolete in Mbed TLS 3.x, since it enforces properties the configuration as adjusted by `mbedtls/build_info.h`, not properties that the user configuration is expected to meet.

### Changes to TLS options

#### Enabling null cipher suites

The option to enable null cipher suites in TLS 1.2 has been renamed from `MBEDTLS_CIPHER_NULL_CIPHER` to `MBEDTLS_SSL_NULL_CIPHERSUITES`. It remains disabled in the default configuration.

#### Removal of backward compatibility options

The option `MBEDTLS_SSL_DTLS_CONNECTION_ID_COMPAT` has been removed. Only the version standardized in RFC 9146 is supported now.
