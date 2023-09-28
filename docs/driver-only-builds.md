This document explains how to create builds of Mbed TLS where some
cryptographic mechanisms are provided only by PSA drivers (that is, no
built-in implementation of those algorithms), from a user's perspective.

This is useful to save code size for people who are using either a hardware
accelerator, or an alternative software implementation that is more
aggressively optimized for code size than the default one in Mbed TLS.

General considerations
----------------------

This document assumes that you already have a working driver.
Otherwise, please see the [PSA driver example and
guide](psa-driver-example-and-guide.md) for information on writing a
driver.

In order to have some mechanism provided only by a driver, you'll want
the following compile-time configuration options enabled:
- `MBEDTLS_PSA_CRYPTO_C` (enabled by default) - this enables PSA Crypto.
- `MBEDTLS_USE_PSA_CRYPTO` (disabled by default) - this makes PK, X.509 and
  TLS use PSA Crypto. You need to enable this if you're using PK, X.509 or TLS
and want them to have access to the algorithms provided by your driver. (See
[the dedicated document](use-psa-crypto.md) for details.)
- `MBEDTLS_PSA_CRYPTO_CONFIG` (disabled by default) - this enables
  configuration of cryptographic algorithms using `PSA_WANT` macros in
`include/psa/crypto_config.h`. See [Conditional inclusion of cryptographic
mechanism through the PSA API in Mbed
TLS](proposed/psa-conditional-inclusion-c.md) for details.

In addition, for each mechanism you want provided only by your driver:
- Define the corresponding `PSA_WANT` macro in `psa/crypto_config.h` - this
  means the algorithm will be available in the PSA Crypto API.
- Define the corresponding `MBEDTLS_PSA_ACCEL` in your build. This could be
  defined in `psa/crypto_config.h` or your compiler's command line. This
informs the PSA code that an accelerator is available for this mechanism.
- Undefine / comment out the corresponding `MBEDTLS_xxx_C` macro in
  `mbedtls/mbedtls_config.h`. This ensures the built-in implementation is not
included in the build.

For example, if you want SHA-256 to be provided only by a driver, you'll want
`PSA_WANT_ALG_SHA_256` and `MBEDTLS_PSA_ACCEL_SHA_256` defined, and
`MBEDTLS_SHA256_C` undefined.

In addition to these compile-time considerations, at runtime you'll need to
make sure you call `psa_crypto_init()` before any function that uses the
driver-only mechanisms. Note that this is already a requirement for any use of
the PSA Crypto API, as well as for use of the PK, X.509 and TLS modules when
`MBEDTLS_USE_PSA_CRYPTO` is enabled, so in most cases your application will
already be doing this.

Mechanisms covered
------------------

For now, only the following (families of) mechanisms are supported:
- hashes: SHA-3, SHA-2, SHA-1, MD5, etc.
- elliptic-curve cryptography (ECC): ECDH, ECDSA, EC J-PAKE, ECC key types.
- finite-field Diffie-Hellman: FFDH algorithm, DH key types.

Supported means that when those are provided only by drivers, everything
(including PK, X.509 and TLS if `MBEDTLS_USE_PSA_CRYPTO` is enabled) should
work in the same way as if the mechanisms where built-in, except as documented
in the "Limitations" sub-sections of the sections dedicated to each family
below.

In the near future (end of 2023), we are planning to also add support for
ciphers (AES) and AEADs (GCM, CCM, ChachaPoly).

Currently (mid-2023) we don't have plans to extend this to RSA. If
you're interested in driver-only support for RSA, please let us know.

Hashes
------

It is possible to have all hash operations provided only by a driver.

More precisely:
- you can enable `PSA_WANT_ALG_SHA_256` without `MBEDTLS_SHA256_C`, provided
  you have `MBEDTLS_PSA_ACCEL_ALG_SHA_256` enabled;
- and similarly for all supported hash algorithms: `MD5`, `RIPEMD160`,
  `SHA_1`, `SHA_224`, `SHA_256`, `SHA_384`, `SHA_512`, `SHA3_224`, `SHA3_256`,
`SHA3_384`, `SHA3_512`.

In such a build, all crypto operations (via the PSA Crypto API, or non-PSA
APIs), as well as X.509 and TLS, will work as usual, except that direct calls
to low-level hash APIs (`mbedtls_sha256()` etc.) are not possible for the
modules that are disabled.

You need to call `psa_crypto_init()` before any crypto operation that uses
a hash algorithm that is provided only by a driver, as mentioned in [General
considerations](#general-considerations) above.

If you want to check at compile-time whether a certain hash algorithm is
available in the present build of Mbed TLS, regardless of whether it's
provided by a driver or built-in, you should use the following macros:
- for code that uses only the PSA Crypto API: `PSA_WANT_ALG_xxx` from
  `psa/crypto.h`;
- for code that uses non-PSA crypto APIs: `MBEDTLS_MD_CAN_xxx` from
  `mbedtls/md.h`.

Elliptic-curve cryptography (ECC)
---------------------------------

It is possible to have most ECC operations provided only by a driver:
- the ECDH, ECDSA and EC J-PAKE algorithms;
- key import, export, and random generation.

More precisely, if:
- you have driver support for ECC public and using private keys (that is,
`MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_PUBLIC_KEY` and
`MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR_BASIC` are enabled), and
- you have driver support for all ECC curves that are enabled (that is, for
  each `PSA_WANT_ECC_xxx` macro enabled, the corresponding
`MBEDTLS_PSA_ACCEL_ECC_xxx` macros is enabled as well);

then you can:
- enable `PSA_WANT_ALG_ECDH` without `MBEDTLS_ECDH_C`, provided
  `MBEDTLS_PSA_ACCEL_ALG_ECDH` is enabled
- enable `PSA_WANT_ALG_ECDSA` without `MBEDTLS_ECDSA_C`, provided
  `MBEDTLS_PSA_ACCEL_ALG_ECDSA` is enabled;
- enable `PSA_WANT_ALG_JPAKE` without `MBEDTLS_ECJPAKE_C`, provided
  `MBEDTLS_PSA_ACCEL_ALG_JPAKE` is enabled.

In addition, if:
- none of `MBEDTLS_ECDH_C`, `MBEDTLS_ECDSA_C`, `MBEDTLS_ECJPAKE_C` are enabled
  (see conditions above), and
- you have driver support for all enabled ECC key pair operations - that is,
  for each `PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_xxx` macro enabled, the
corresponding `MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR_xxx` macros is also
enabled,

then you can also disable `MBEDTLS_ECP_C`. However, a small subset of it might
still be included in the build, see limitations sub-section below.

In addition, if:
- `MBEDTLS_ECP_C` is fully removed (see limitation sub-section below), and
- support for RSA key types and algorithms is fully disabled, and
- support for DH key types and the FFDH algorithm is either disabled, or
  fully provided by a driver,

then you can also disable `MBEDTLS_BIGNUM_C`.

In such builds, all crypto operations via the PSA Crypto API will work as
usual, as well as the PK, X.509 and TLS modules if `MBEDTLS_USE_PSA_CRYPTO` is
enabled, with the following exceptions:
- direct calls to APIs from the disabled modules are not possible;
- PK, X.509 and TLS will not support restartable ECC operations (see
  limitation sub-section below).

If you want to check at compile-time whether a certain curve is available in
the present build of Mbed TLS, regardless of whether ECC is provided by a
driver or built-in, you should use the following macros:
- for code that uses only the PSA Crypto API: `PSA_WANT_ECC_xxx` from
  `psa/crypto.h`;
- for code that may also use non-PSA crypto APIs: `MBEDTLS_ECP_HAVE_xxx` from
  `mbedtls/build_info.h` where xxx can take the same values as for
`MBEDTLS_ECP_DP_xxx` macros.

Note that for externally-provided drivers, the integrator is responsible for
ensuring the appropriate `MBEDTLS_PSA_ACCEL_xxx` macros are defined. However,
for the p256-m driver that's provided with the library, those macros are
automatically defined when enabling `MBEDTLS_PSA_P256M_DRIVER_ENABLED`.

### Limitations regarding fully removing `ecp.c`

A limited subset of `ecp.c` will still be automatically re-enabled if any of
the following is enabled:
- `MBEDTLS_PK_PARSE_EC_COMPRESSED` - support for parsing ECC keys where the
  public part is in compressed format;
- `MBEDTLS_PK_PARSE_EC_EXTENDED` - support for parsing ECC keys where the
  curve is identified not by name, but by explicit parameters;
- `PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_DERIVE` - support for deterministic
  derivation of an ECC keypair with `psa_key_derivation_output_key()`.

Note: when any of the above options is enabled, a subset of `ecp.c` will
automatically be included in the build in order to support it. Therefore
you can still disable `MBEDTLS_ECP_C` in `mbedtls_config.h` and this will
result in some code size savings, but not as much as when none of the
above features are enabled.

We do have plans to support each of these with `ecp.c` fully removed in the
future, however there is no established timeline. If you're interested, please
let us know, so we can take it into consideration in our planning.

### Limitations regarding restartable / interruptible ECC operations

At the moment, there is no driver support for interruptible operations
(see `psa_sign_hash_start()` + `psa_sign_hash_complete()` etc.) so as a
consequence these are not supported in builds without `MBEDTLS_ECDSA_C`.

Similarly, there is no PSA support for interruptible ECDH operations so these
are not supported without `ECDH_C`. See also limitations regarding
restartable operations with `MBEDTLS_USE_PSA_CRYPTO` in [its
documentation](use-psa-crypto.md).

Again, we have plans to support this in the future but not with an established
timeline, please let us know if you're interested.

### Limitations regarding "mixed" builds (driver and built-in)

In order for a build to be driver-only (no built-in implementation), all the
requested algorithms, key types (key operations) and curves must be
accelerated (plus a few other restrictions, see "Limitations regarding fully
removing `ecp.c`" above). However, what if you have an accelerator that only
supports some algorithms, some key types (key operations), or some curves, but
want to have more enabled in you build?

It is possible to have acceleration for only a subset of the requested
algorithms. In this case, the built-in implementation of the accelerated
algorithms will be disabled, provided all the requested curves and key types
that can be used with this algorithm are also declared as accelerated.

There is very limited support for having acceleration for only a subset of the
requested key type operations. The only configuration that's tested is that of
a driver accelerating `PUBLIC_KEY`, `KEY_PAIR_BASIC`, `KEY_PAIR_IMPORT`,
`KEY_PAIR_EXPORT` but not `KEY_PAIR_GENERATE`. (Note: currently the driver
interface does not support `KEY_PAIR_DERIVE`.)

There is limited support for having acceleration for only a subset of the
requested curves. In such builds, only the PSA API is currently tested and
working; there are known issues in PK, and X.509 and TLS are untested.

Finite-field Diffie-Hellman
---------------------------

Support is pretty similar to the "Elliptic-curve cryptography (ECC)" section
above.
Key management and usage can be enabled by means of the usual `PSA_WANT` +
`MBEDTLS_PSA_ACCEL` pairs:

- `[PSA_WANT|MBEDTLS_PSA_ACCEL]_KEY_TYPE_DH_PUBLIC_KEY`;
- `[PSA_WANT|MBEDTLS_PSA_ACCEL]_KEY_TYPE_DH_KEY_PAIR_BASIC`;
- `[PSA_WANT|MBEDTLS_PSA_ACCEL]_KEY_TYPE_DH_KEY_PAIR_IMPORT`;
- `[PSA_WANT|MBEDTLS_PSA_ACCEL]_KEY_TYPE_DH_KEY_PAIR_EXPORT`;
- `[PSA_WANT|MBEDTLS_PSA_ACCEL]_KEY_TYPE_DH_KEY_PAIR_GENERATE`;

The same holds for the associated algorithm:
`[PSA_WANT|MBEDTLS_PSA_ACCEL]_ALG_FFDH` allow builds accelerating FFDH and
removing builtin support (i.e. `MBEDTLS_DHM_C`).

### Limitations
Support for deterministic derivation of a DH keypair
(i.e. `PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_DERIVE`) is not supported.
