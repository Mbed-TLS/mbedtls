Strengthen default algorithm selection for X.509 and TLS
--------------------------------------------------------

The default X.509 verification profile (`mbedtls_x509_crt_profile_default`) and the default curve and hash selection in TLS have changed. They are now aligned, except that the X.509 profile only lists curves that support signature verification.

Hashes and curves weaker than 255 bits (security strength less than 128 bits) are no longer accepted by default. The following hashes have been removed: SHA-1 (formerly only accepted for key exchanges but not for certificate signatures), SHA-224 (weaker hashes were already not accepted). The following curves have been removed: secp192r1, secp224r1, secp192k1, secp224k1.

The compile-time options `MBEDTLS_TLS_DEFAULT_ALLOW_SHA1_IN_CERTIFICATES` and `MBEDTLS_TLS_DEFAULT_ALLOW_SHA1_IN_KEY_EXCHANGE` are no longer available.

The curve secp256k1 has also been removed from the default X.509 and TLS profiles. [RFC 8422](https://datatracker.ietf.org/doc/html/rfc8422#section-5.1.1) deprecates it in TLS, and it is very rarely used, although it is not known to be weak at the time of writing.

If you still need to accept certificates signed with algorithms that have been removed from the default profile, call `mbedtls_x509_crt_verify_with_profile` instead of `mbedtls_x509_crt_verify` and pass a profile that allows the curves and hashes you want. For example, to allow SHA-224:
```
mbedtls_x509_crt_profile my_profile = mbedtls_x509_crt_profile_default;
my_profile.allowed_mds |= MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA224 );
```

If you still need to allow hashes and curves in TLS that have been removed from the default configuration, call `mbedtls_ssl_conf_sig_hashes()` and `mbedtls_ssl_conf_curves()` with the desired lists.

TLS now favors faster curves over larger curves
-----------------------------------------------

The default preference order for curves in TLS now favors resource usage (performance and memory consumption) over size. The exact order is unspecified and may change, but generally you can expect 256-bit curves to be preferred over larger curves.

If you prefer a different order, call `mbedtls_ssl_conf_curves()` when configuring a TLS connection.
