Remove the truncated HMAC extension
-----------------------------------

This affects all users who use the truncated HMAC extension for cryptographic
operations.

The config option `MBEDTLS_SSL_TRUNCATED_HMAC` has been removed. Users concerned
about overhead are better served by using any of the CCM-8 ciphersuites rather
than a CBC ciphersuite with truncated HMAC, and so going forward this must be
the approach taken.
