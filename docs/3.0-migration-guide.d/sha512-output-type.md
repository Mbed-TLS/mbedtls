SHA-512 output type change
--------------------------

The output parameter of `mbedtls_sha512_finish_ret()` and `mbedtls_sha512_ret()` now has a pointer type rather than array type. This makes no difference in terms of C semantics, but removes spurious warnings in some compilers when outputting a SHA-384 hash into a 48-byte buffer.

This makes no difference to a vast majority of applications. If your code takes a pointer to one of these functions, you may need to change the type of the pointer.

Alternative implementations of the SHA512 module must adjust their functions' prototype accordingly.
