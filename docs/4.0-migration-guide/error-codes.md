## Error codes

### Unified error code space

The convention still applies that functions return 0 for success and a negative value between -32767 and -1 on error. PSA functions (`psa_xxx()` or `mbedtls_psa_xxx()`) still return a `PSA_ERROR_xxx` error codes. Non-PSA functions (`mbedtls_xxx()` excluding `mbedtls_psa_xxx()`) can return either `PSA_ERROR_xxx` or `MBEDTLS_ERR_xxx` error codes.

There may be cases where an `MBEDTLS_ERR_xxx` constant has the same numerical value as a `PSA_ERROR_xxx`. In such cases, they have the same meaning: they are different names for the same error condition.

### Simplified legacy error codes

All values returned by a function to indicate an error now have a defined constant named `MBEDTLS_ERR_xxx` or `PSA_ERROR_xxx`. Functions no longer return the sum of a “low-level” and a “high-level” error code.

Generally, functions that used to return the sum of two error codes now return the low-level code. However, as before, the exact error code returned in a given scenario can change without notice unless the condition is specifically described in the function's documentation and no other condition is applicable.

As a consequence, the functions `mbedtls_low_level_strerr()` and `mbedtls_high_level_strerr()` no longer exist.

### Removed error code names

Many legacy error codes have been removed in favor of PSA error codes. Generally, functions that returned a legacy error code in the table below in Mbed TLS 3.6 now return the PSA error code listed on the same row. Similarly, callbacks should apply the same changes to error code, unless there has been a relevant change to the callback's interface.

| Legacy constant (Mbed TLS 3.6)          | PSA constant (Mbed TLS 4.0)     |
|-----------------------------------------|---------------------------------|
| `MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED` | `PSA_ERROR_CORRUPTION_DETECTED` |
| `MBEDTLS_ERR_ERROR_GENERIC_ERROR`       | `PSA_ERROR_GENERIC_ERROR`       |
| `MBEDTLS_ERR_NET_BUFFER_TOO_SMALL`      | `PSA_ERROR_BUFFER_TOO_SMALL`    |
| `MBEDTLS_ERR_OID_BUF_TOO_SMALL`         | `PSA_ERROR_BUFFER_TOO_SMALL`    |
| `MBEDTLS_ERR_OID_NOT_FOUND`             | `PSA_ERROR_NOT_SUPPORTED`       |
| `MBEDTLS_ERR_PKCS7_ALLOC_FAILED`        | `PSA_ERROR_INSUFFICIENT_MEMORY` |
| `MBEDTLS_ERR_PKCS7_BAD_INPUT_DATA`      | `PSA_ERROR_INVALID_ARGUMENT`    |
| `MBEDTLS_ERR_PKCS7_VERIFY_FAIL`         | `PSA_ERROR_INVALID_SIGNATURE`   |
| `MBEDTLS_ERR_SSL_ALLOC_FAILED`          | `PSA_ERROR_INSUFFICIENT_MEMORY` |
| `MBEDTLS_ERR_SSL_BAD_INPUT_DATA`        | `PSA_ERROR_INVALID_ARGUMENT`    |
| `MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL`      | `PSA_ERROR_BUFFER_TOO_SMALL`    |
| `MBEDTLS_ERR_X509_ALLOC_FAILED`         | `PSA_ERROR_INSUFFICIENT_MEMORY` |
| `MBEDTLS_ERR_X509_BUFFER_TOO_SMALL`     | `PSA_ERROR_BUFFER_TOO_SMALL`    |

See also the corresponding section in the TF-PSA-Crypto migration guide, which lists error codes from cryptography modules.
