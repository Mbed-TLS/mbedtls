SHA-512 and SHA-256 output type change
--------------------------

The output parameter of `mbedtls_sha256_finish_ret()`, `mbedtls_sha256_ret()`, `mbedtls_sha512_finish_ret()`, `mbedtls_sha512_ret()` now has a pointer type rather than array type. This makes no difference in terms of C semantics, but removes spurious warnings in some compilers when outputting a SHA-384 hash into a 48-byte buffer or a SHA-224 hash into a 28-byte buffer.

This makes no difference to a vast majority of applications. If your code takes a pointer to one of these functions, you may need to change the type of the pointer.

Alternative implementations of the SHA256 and SHA512 modules must adjust their functions' prototype accordingly.
