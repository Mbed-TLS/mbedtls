## Error codes

### Unified error code space

The convention still applies that functions return 0 for success and a negative value between -32767 and -1 on error. PSA functions (`psa_xxx()` or `mbedtls_psa_xxx()`) still return a `PSA_ERROR_xxx` error codes. Non-PSA functions (`mbedtls_xxx()` excluding `mbedtls_psa_xxx()`) can return either `PSA_ERROR_xxx` or `MBEDTLS_ERR_xxx` error codes.

There may be cases where an `MBEDTLS_ERR_xxx` constant has the same numerical value as a `PSA_ERROR_xxx`. In such cases, they have the same meaning: they are different names for the same error condition.

### Simplified legacy error codes

All values returned by a function to indicate an error now have a defined constant named `MBEDTLS_ERR_xxx` or `PSA_ERROR_xxx`. Functions no longer return the sum of a “low-level” and a “high-level” error code.

Generally, functions that used to return the sum of two error codes now return the low-level code. However, as before, the exact error code returned in a given scenario can change without notice unless the condition is specifically described in the function's documentation and no other condition is applicable.

As a consequence, the functions `mbedtls_low_level_sterr()` and `mbedtls_high_level_strerr()` no longer exist.

### Removed error code names

Many legacy error codes have been removed in favor of PSA error codes. Generally, functions that returned a legacy error code in the table below in Mbed TLS 3.6 now return the PSA error code listed on the same row. Similarly, callbacks should apply the same changes to error code, unless there has been a relevant change to the callback's interface.

| Legacy constant (Mbed TLS 3.6) | PSA constant (Mbed TLS 4.0, TF-PSA-Crypto 1.0) |
| ------------------------------ | ---------------------------------------------- |
| `MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED` | `PSA_ERROR_CORRUPTION_DETECTED` |
| `MBEDTLS_ERR_ERROR_GENERIC_ERROR` | `PSA_ERROR_GENERIC_ERROR` |
| `MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED` | `PSA_ERROR_NOT_SUPPORTED` |
| `MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED` | `PSA_ERROR_HARDWARE_FAILURE` |
| `MBEDTLS_ERR_ECP_IN_PROGRESS` | `PSA_OPERATION_INCOMPLETE` |
| `MBEDTLS_ERR_RSA_VERIFY_FAILED` | `PSA_ERROR_INVALID_SIGNATURE` |
