The RNG parameter is now mandatory for all functions that accept one
--------------------------------------------------------------------

This change affects all users who called a function accepting a `f_rng`
parameter with `NULL` as the value of this argument; this is no longer
supported.

The changed functions are: the X.509 CRT and CSR writing functions; the PK and
RSA sign and decrypt functions; `mbedtls_rsa_private()`; the functions in DHM
and ECDH that compute the shared secret; the scalar multiplication functions in
ECP.

You now need to pass a properly seeded, cryptographically secure RNG to all
functions that accept a `f_rng` parameter. It is of course still possible to
pass `NULL` as the context pointer `p_rng` if your RNG function doesn't need a
context.

Alternative implementations of a module (enabled with the `MBEDTLS_module_ALT`
configuration options) may have their own internal and are free to ignore the
`f_rng` argument but must allow users to pass one anyway.

Some functions gained an RNG parameter
--------------------------------------

This affects users of the following functions: `mbedtls_ecp_check_pub_priv()`,
`mbedtls_pk_check_pair()`, `mbedtls_pk_parse_key()`, and
`mbedtls_pk_parse_keyfile()`.

You now need to pass a properly seeded, cryptographically secure RNG when
calling these functions. It is used for blinding, a counter-measure against
side-channel attacks.

The configuration option `MBEDTLS_ECP_NO_INTERNAL_RNG` was removed
------------------------------------------------------------------

This doesn't affect users of the default configuration; it only affects people
who were explicitly setting this option.

This was a trade-off between code size and counter-measures; it is no longer
relevant as the counter-measure is now always on at no cost in code size.
