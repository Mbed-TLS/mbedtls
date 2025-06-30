## PSA as the only cryptography API

The PSA API is now the only API for cryptographic primitives.

### Impact on application code

The X.509, PKCS7 and SSL modules always use PSA for cryptography, with a few exceptions documented in the [PSA limitations](../architecture/psa-migration/psa-limitations.md) document. (These limitations are mostly transparent unless you want to leverage PSA accelerator drivers.) This corresponds to the behavior of Mbed TLS 3.x when `MBEDTLS_USE_PSA_CRYPTO` is enabled. In effect, `MBEDTLS_USE_PSA_CRYPTO` is now always enabled.

`psa_crypto_init()` must be called before performing any cryptographic operation, including indirect requests such as parsing a key or certificate or starting a TLS handshake.

A few functions take different parameters to migrate them to the PSA API. See “[Function prototype changes](#function-prototype-changes)”.

### No random generator instantiation

Formerly, applications using TLS, asymmetric cryptography operations involving a private key, or other features needing random numbers, needed to provide a random generator, generally by instantiating an entropy context (`mbedtls_entropy_context`) and a DRBG context (`mbedtls_ctr_drbg_context` or `mbedtls_hmac_drbg_context`). This is no longer necessary, or possible. All features that require a random generator (RNG) now use the one provided by the PSA subsystem.

Instead, applications that use random generators or keys (even public keys) need to call `psa_crypto_init()` before any cryptographic operation or key management operation.

See also [function prototype changes](#function-prototype-changes), many of which are related to the move from RNG callbacks to a global RNG.

### Impact on the library configuration

Mbed TLS follows the configuration of TF-PSA-Crypto with respect to cryptographic mechanisms. They are now based on `PSA_WANT_xxx` macros instead of legacy configuration macros such as `MBEDTLS_RSA_C`, `MBEDTLS_PKCS1_V15`, etc. The configuration of X.509 and TLS is not directly affected by the configuration. However, applications and middleware that rely on these configuration symbols to know which cryptographic mechanisms to support will need to migrate to `PSA_WANT_xxx` macros. For more information, consult the PSA transition guide in TF-PSA-Crypto.
