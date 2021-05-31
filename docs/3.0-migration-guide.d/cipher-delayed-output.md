Calling `mbedtls_cipher_finish()` is mandatory for all multi-part operations
----------------------------------------------------------------------------

This only affect people who use the Cipher module to perform AEAD operations
using the multi-part API.

Previously, the documentation didn't state explicitly if it was OK to call
`mbedtls_cipher_check_tag()` or `mbedtls_cipher_write_tag()` directly after
the last call to `mbedtls_cipher_update()` - that is, without calling
`mbedtls_cipher_finish()` in-between. If you code was missing that call,
please add it and be prepared to get as much as 15 bytes of output.

Currently the output is always 0 bytes, but it may be more when alternative
implementations of the underlying primitives are in use, or with future
versions of the library.
