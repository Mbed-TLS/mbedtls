Weak curves are now disabled by default for X.509 and TLS
---------------------------------------------------------

The default X.509 verification profile (`mbedtls_x509_crt_profile_default`) and the default curve and hash selection have changed. X.509 and TLS now allow the same algorithms by default (except that the X.509 profile only lists curves that support signature verification).

Hashes and curves weaker than 255 bits are no longer accepted by default. The following algorithms have been removed: SHA-1 (formerly only accepted for key exchanges but not for certificate signatures), SHA-224, secp192r1, secp224r1, secp192k1, secp224k1 (weaker hashes were already not accepted).

The compile-time option `MBEDTLS_TLS_DEFAULT_ALLOW_SHA1_IN_KEY_EXCHANGE` is no longer available.

If you still need to accept certificates signed with algorithms that have been removed from the default profile, call `mbedtls_x509_crt_verify_with_profile` instead of `mbedtls_x509_crt_verify` and pass a profile that allows the curves you want. For example, to allow SHA-224:
```
mbedtls_x509_crt_profile my_profile = mbedtls_x509_crt_profile_default;
my_profile.allowed_mds |= MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA224 );
```

If you still need to allow hashes and curves in TLS that have been removed from the default configuration, call `mbedtls_ssl_conf_sig_hashes()` and `mbedtls_ssl_conf_curves()` with the desired lists.

TLS now favors faster curves over larger curves
-----------------------------------------------

The default preference order for curves in TLS now favors resource usage (performance and memory consumption) over size. The exact order is unspecified and may change, but generally you can expect 256-bit curves to be preferred.

If you prefer a different order, call `mbedtls_ssl_conf_curves()` when configuring a TLS connection.
