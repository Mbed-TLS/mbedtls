This document explains feature guards macros to be used during the transition
from legacy to PSA in order to determine whether a given cryptographic
mechanism is available in the current build.

We currently (as of Mbed TLS 3.6) have three sets of feature macros:
- `PSA_WANT` macros;
- legacy `MBEDTLS_xxx` macros;
- transitional `MBEDTLS_xxx` macros that stem from the desire to be able to
  use crypto mechanisms that are only provided by a driver (G5 in
`strategy.md`).

This document's goal is to shed some light on when to use which. It is mostly
intended for maintainers.

Since most transition macros come from driver-only work, it can be useful to
check `docs/driver-only-builds.md` as well for background. (Note: as
maintainers, for the best precision about what's supported of not with
drivers, check the relevant `component_test_psa_crypto_config_accel_xxx`'s
configuration, as well as the corresponding exclude list in
`analyze_outcomes.py`.)

General considerations
======================

This document only applies to Mbed TLS 3.6 TLS. By contrast:
- in 2.28 we have no driver-only support, so the legacy guards `MBEDTLS_XXX`
  should be used everywhere;
- in 4.0 configuration will be purely based on PSA, so `PSA_WANT` macros
  should be used everywhere.

It is useful to consider the following domains:
- The PSA domain: things declared in `include/psa/*.h`, implemented in
  `library/psa_*.c` and tested in `tests/suites/test_suite_psa*`.
- The pure TLS 1.3 domain: the parts of TLS 1.3 that are not in the `USE_PSA`
  domain (see below). Those use PSA APIs unconditionally.
- The `USE_PSA` domain (that is, code that calls PSA crypto APIs when
  `USE_PSA` is enabled, and legacy crypto APIs otherwise): that's PK, X.509,
most of TLS 1.2 and the parts of TLS 1.3 that are common with TLS 1.2 or are
about public/private keys (see `docs/use-psa-crypto.md` for details).
- The legacy crypto domain: a number of modules there will use crypto from
  other modules, for example RSA and entropy will use hashes, PEM will use
hashes and ciphers (from encrypted PEM), etc.

The first two categories (PSA domain, pure TLS 1.3 domain) are simple: as a
general rule, use `PSA_WANT` macros. (With very few exceptions, see
`component_check_test_dependencies` in `all.sh`.) In the rare instances where it is necessary to
check whether a mechanism is built-in or provided by a driver,
`MBEDTLS_PSA_BUILTIN_xxx` and `MBEDTLS_PSA_ACCEL_xxx` macros should be used
(but not legacy `MBEDTLS_xxx` macros).

For the `USE_PSA` domain, it should always be correct to use expressions like
`(!USE_PSA && MBEDTLS_xxx) || (USE_PSA && PSA_WANT_xxx)`. Sometimes, macros
are defined in order to avoid using long expressions everywhere; they will be
mentioned in the following sections.

The remaining category, the legacy domain, tends to be more complex. There are
different rules for different families of mechanisms, as detailed in the
following sections.

Symmetric crypto
================

Hashes
------

**Hash vs HMAC:** Historically (since 2.0) we've had the generic hash
interface, and the implementation of HMAC, in the same file controlled by a
single feature macro: `MBEDTLS_MD_C`. This has now been split in two:
- `MBEDTLS_MD_LIGHT` is about the generic hash interface; we could think of it
  as `MBEDTLS_HASH_C`.
- `MBEDTLS_MD_C` is about the HMAC implementation; we could think of it as
  `MBEDTLS_HMAC_C` (auto-enabling `MBEDTLS_HASH_C`).

(In fact, this is not the whole story: `MD_LIGHT` is the _core_ of the generic
hash interface, excluding functions such as `mbedtls_md_list()` and
`mbedtls_md_info_from_string()`, `mbedtls_md_file()`, etc. But I think the
above should still provide a good intuition as first approximation.)

Note that all users of hashes in the library use either the PSA Crypto API or the `md.h` API.
That is, no user in the library, even in the legacy domain, uses the low-level hash APIs
(`mbedtls_sha256` etc). (That's not true of all example programs, though.)

**Helper macros:** in `config_adjust_legacy_crypto.h` we define a family of
macro `MBEDTLS_MD_CAN_xxx`. These macros are defined (for available hashes) as
soon as `MBEDTLS_MD_LIGHT` is enabled. This subset of `MD` is automatically
enabled as soon as something from the legacy domain, or from the `USE_PSA`
domain, needs a hash. (Note that this includes `ENTROPY_C`, so in practice
`MD_LIGHT` is enabled in most builds.)

Note that there is a rule, enforced by `config_adjust_psa_superset_legacy.h`,
that as soon as `PSA_CRYPTO_C` is enabled, all hashes that are enabled on the
legacy side are also enabled on the PSA side (the converse is not true: a hash
that's provided by a driver will typically be available only on the PSA side). So, in
practice, when `PSA_CRYPTO_C` and `MD_LIGHT` are both enabled,
`PSA_WANT_ALG_xxx` and `MBEDTLS_MD_CAN_xxx` are equivalent.

**Legacy and `USE_PSA` domains:** for hashes, `MBEDTLS_MD_CAN_xxx` (where
`xxx` is the legacy name of the hash) can be used everywhere (except in the
PSA domain which should use `PSA_WANT` as usual). No special include is
required, `build_info.h` or `common.h` is enough.

**Pure TLS 1.3 domain:** it is not easy to know which uses of hashes fall in
this domain as opposed to the `USE_PSA` domain whithout looking at the code.
Fortunately, `MD_CAN` and `PSA_WANT` macros can be used interchangeably, as
per the note above.

HMAC
----

**Legacy domain:** the code is using the `md.h` API. For this domain,
availability of HMAC-xxx is determined by `MBEDTLS_MD_C && MBEDTLS_MD_CAN_xxx`
(see previous subsection about `MD_CAN`). Modules in this domain that may use
HMAC are PKCS5, PKCS7, HKDF, HMAC-DRBG and ECDSA deterministic.

**`USE_PSA` domain:** code will use the `md.h` API when `USE_PSA` is disabled,
and the `psa_mac` API when `USE_PSA` is enabled. It should check for the
availability of HMAC-xxx with either:
```
((!MBEDTLS_USE_PSA_CRYPTO && MBEDTLS_MD_C) ||
 (MBEDTLS_USE_PSA_CRYPTO && PSA_WANT_ALG_HMAC)) &&
MBEDTLS_MD_CAN_xxx
```
or
```
(!MBEDTLS_USE_PSA_CRYPTO && MBEDTLS_MD_C && MBEDTLS_xxx_C) ||
(MBEDTLS_USE_PSA_CRYPTO && PSA_WANT_ALG_HMAC && PSA_WANT_ALG_xxx)
```
or any equivalent condition (see note at the end of the previous section).
The only module in this case is TLS, which currently depends on
`USE_PSA_CRYPTO || MD_C`.

Note: while writing this, it occurs to me that TLS 1.2 does not seem to be
checking for `PSA_WANT_ALG_HMAC` before enabling CBC ciphersuites when
`USE_PSA` is enabled, which I think it should. Builds with `USE_PSA` enabled,
`PSA_WANT_ALG_HMAC` disabled and other requirements for CBC ciphersuites
enabled, are probably broken (perhaps only at runtime when a CBC ciphersuite
is negotiated).

**Pure TLS 1.3 domain:** HMAC is used for the Finished message via PSA Crypto
APIs. So, TLS 1.3 should depend on `PSA_WANT_ALG_HMAC` - doesn't seem to be
enforced by `check_config.h`, or documented in `mbedtls_config.h`, at the
moment.

Ciphers (AEAD and unauthenticated)
----------------------------------

**Overview of existing (internal) APIs:** we currently have 5 (families of)
APIs for ciphers (and associated constructs) in the library:
- Low-level API for primitives: `mbedtls_aes_xxx` etc. - used by `cipher.c`
  and some other modules in the legacy domain.
- Internal abstraction layer `block_cipher` for AES, ARIA and Camellia
  primitives - used only by `gcm.c` and `ccm.c`, only when `CIPHER_C` is not
enabled (for compatibility reasons).
- Block cipher modes / derivatives:
  - `mbedtls_gcm_xxx` and `mbedtls_ccm_xxx`, used by `cipher.c` and
    the built-in PSA implementation;
  - `mbedtls_nist_kw_xxx`, used by `cipher.c`;
  - `mbedtls_cipher_cmac_xxx`, used by the built-in PSA implementation;
  - `mbedtls_ctr_drbg_xxx`, used by PSA crypto's RNG subsystem.
- Cipher: used by some modules in the legacy domain, and by the built-in PSA
  implementation.
- PSA: used by the `USE_PSA` domain when `MBEDTLS_USE_PSA_CRYPTO` is enabled.

**Legacy domain:** most code here is using either `cipher.h` or low-level APIs
like `aes.h`, and should use legacy macros like `MBEDTLS_AES_C` and
`MBEDTLS_CIPHER_MODE_CBC`. This includes NIST-KW, CMAC, PKCS5/PKCS12 en/decryption
functions, PEM decryption, PK parsing of encrypted keys. The only exceptions
are:
1. `GCM` and `CCM` use the internal abstraction layer `block_cipher` and check
   for availability of block ciphers using `MBEDTLS_CCM_GCM_CAN_xxx` macros
defined in `config_adjut_legacy_crypto.h`. As a user, to check if AES-GCM is
available through the `mbedtls_gcm` API, you want to check for `MBEDTLS_GCM_C`
and `MBDTLS_CCM_GCM_CAN_AES`.
2. `CTR_DRBG` uses the low-level `mbedtls_aes_` API if it's available,
  otherwise it uses the PSA API. There is no need for users of `CTR_DRBG` to
check if AES is available: `check_config.h` is already taking care of that, so
from a user's perspective as soon as `MBEDTLS_CTR_DRBG_C` is enabled, you can
use it without worrying about AES.

**`USE_PSA` domain:** here we should use conditions like the following in
order to test for availability of ciphers and associated modes.
```
// is AES available?
(!defined(MBEDTLS_USE_PSA_CRYPTO) && defined(MBEDTLS_AES_C)) || \
(defined(MBEDTLS_USE_PSA_CRYPTO) && defined(PSA_WANT_KEY_TYPE_AES))
// is CBC available?
(!defined(MBEDTLS_USE_PSA_CRYPTO) && defined(MBEDTLS_CIPHER_MODE_CBC)) || \
(defined(MBEDTLS_USE_PSA_CRYPTO) && defined(PSA_WANT_ALG_CBC_NO_PADDING))
// is GCM available?
(!defined(MBEDTLS_USE_PSA_CRYPTO) && defined(MBEDTLS_GCM_C)) || \
(defined(MBEDTLS_USE_PSA_CRYPTO) && defined(PSA_WANT_ALG_GCM))
```
Note: TLS is the only user of ciphers in the `USE_PSA` domain, and it defines
`MBEDTLS_SSL_HAVE_xxx` macros in `config_adjust_legacy_crypto.h` for the
ciphers and modes it needs to know about.

**Pure TLS 1.3 domain:** none. All from TLS 1.3 are in the `USE_PSA` domain
(common to TLS 1.2).

Key derivation
--------------

**Legacy domain:** the modules PKCS5 and PKCS12 both provide
key derivation (respectively PBKDF2-HMAC and PKCS12 derivation), and use it
for password-based encryption. (Note: PEM has an implementation of PBKDF1 but
it's internal.)

**`USE_PSA` domain:** PK (parse) will use PKCS5 and PKCS12 encryption (hence
indirectly key derivation) if present in the build. The macros are
`MBEDTLS_PKCS5_C` and `MBEDTLS_PKCS12_C`. Note that even when `USE_PSA` is
enabled, PK parse will _not_ use PSA for the PBKDF2 part of PKCS5 decryption.

**Pure TLS 1.3 domain:** TLS 1.3 is using HKDF via PSA Crypto APIs. We already
enforce in `check_config.h` that TLS 1.3 depends on the appropriate `PSA_WANT`
macros.

Asymmetric crypto
=================

RSA
---

**Legacy domain and `USE_PSA` domain:** use `RSA_C` everywhere. (Note: there's
no user of RSA in the legacy domain, and the only direct user in the `USE_PSA`
domain is PK - both X.509 and TLS will only RSA via PK.)

**Pure TLS 1.3 domain:** no use of RSA in this domain. All TLS 1.3 uses of RSA
go through PK, hence are in the `USE_PSA` domain.

FFDH
----

**Legacy domain and `USE_PSA` domain:** use `DHM_C`. The only user is TLS 1.2
which is actually in the legacy domain - this is an exception where `USE_PSA`
has no effect, because PSA doesn't cover the needs of TLS 1.2 here.

**Pure TLS 1.3 domain:** use `PSA_WANT`. The TLS 1.3 code for Diffie-Hellman
is common to ECDH and FFDH thanks to PSA Crypto APIs being generic enough. The
parts about FFDH are guarded with `PSA_WANT_ALG_FFDH` (with the reasoning that
this implies support for the corresponding key type).

ECC
---

**Curves:** in `config_adjut_psa_superset_legacy.h` we ensure that, as soon as
`PSA_CRYPTO_C` is enabled, all
curves that are supported on the legacy side (`MBEDTLS_ECP_DP_xxx_ENABLED`)
are also supported on the PSA side (`PSA_WANT_ECC_xxx`). (The converse is not
true as a curve provided by a driver will typically only be available on the
PSA side).

In `config_adjust_legacy_crypto.h` we define macros `MBEDTLS_ECP_HAVE_xxx`.
These macros are useful for data and functions that have users in several
domains, such as `mbedtls_ecc_group_to_psa()`, or that have users only in the
`USE_PSA` domain but want a simpler (if sub-optimal) condition, such as
`mbedtls_oid_get_ec_grp()`.

Strictly speaking, code in the `USE_PSA` domain should not use the above
`MBEDTLS_ECP_HAVE_xxx` macros but conditions like
```
(!MBEDTLS_USE_PSA_CRYPTO && MBEDTLS_ECP_DP_xxx_ENABLED) ||
(MBEDTLS_USE_PSA_CRYPTO && PSA_WANT_ECC_xxx)
```
Note while writing: a lot of tests for things in the `USE_PSA` domain appear
to be using `MBEDTLS_ECP_HAVE_xxx`. IMO this is incorrect, but not caught by
the CI because I guess we don't run tests in configurations that have both
`USE_PSA_CRYPTO` disabled, and some curves enabled only on the PSA side. My
initial feeling is we don't care about such configurations as this point, and
can leave the dependencies as they are until they're replaced with `PSA_WANT`
macros in 4.0 anyway.

**Legacy domain:** use the legacy macros `ECP_C`, `ECDH_C`, `ECDSA_C`,
`ECJPAKE_C`, `MBEDTLS_ECP_DP_xxx_ENABLED`. (This is mostly just ECDH, ECDSA
and EC J-PAKE using ECP.)

**Key management, `USE_PSA` domain:** `MBEDTLS_PK_HAVE_ECC_KEYS` means that PK
supports ECC key parsing and writing (and storage). It does not imply support
for doing crypto operation with such keys - see `MBEDTLS_PK_CAN_ECDSA_xxx`
above for that.

**ECDH, `USE_PSA` domain:** this is just TLS 1.2. It's using the helper macro
`MBEDTLS_CAN_ECDH` defined in `config_adjust_legacy_crypto.h` (which should
probably be called `MBEDTLS_SSL_TLS1_2_CAN_ECDH` as it's only for TLS 1.2).
(Note: the macro is not used directly in the code, it's only used as a
dependency for relevant TLS 1.2 key exchanges. Then the code uses the guards
for the key exchanges.)

**ECDH, pure TLS 1.3 domain:** using `PSA_WANT_ALG_ECDH`.

**ECDSA, `USE_PSA` domain:** should use the macros
`MBEDTLS_PK_CAN_ECDSA_{SIGN,VERIFY,SOME}` that indicate support for signature
generation, verification, or at least one of those, respectively. To check for
support for signatures with a specific hash, combine
`MBEDTLS_PK_CAN_ECDSA_xxx` with `MBEDTLS_MD_CAN_xxx`.

**ECDSA, pure TLS 1.3 domain:** none - everything goes through PK.

**EC J-PAKE, `USE_PSA` domain:** only used by TLS 1.2. The code is guarded by
the corresponding `KEY_EXCHANGE` macro, which in `check_config.h` depends on
the appropriate macros depending on whether `USE_PSA` is on or off.

**EC J-PAKE, pure TLS 1.3 domain:** none - EC J-PAKE is TLS 1.2 (so far).

**Related internal macros:**
- `MBEDTLS_PK_USE_PSA_EC_DATA` is an internal switch of the PK module. When
  it's not defined, PK stores ECC keys as a `struct mbedtls_ecxxx_keypair`;
when it's defined, PK stores in a PSA -friendly format instead (PSA key slot
for private keys, metadata + array of bytes with the PSA import/export format
for the public part). This macro is only defined when `ECP_C` is not and
`USE_PSA` is, see comments above its definition in `pk.h` for details.
- `MBEDTLS_ECP_LIGHT` enables only a subset of `ecp.c`. This subset is pretty
  much ad hoc: it's basically everything that doesn't depend on scalar
multiplication (_the_ complex expensive operation in ECC arithmetic).
Basically, this subset gives access to curve data (constants), key storage,
basic parsing and writing. It is auto-enabled in some driver-only
configurations where the user has disabled `ECP_C` because they have drivers
for the crypto operations they use, but they've also asked for some things
that are not supported by drivers yet, such as deterministic key derivation,
or parsing of compressed keys - on those cases, `ECP_LIGHT` will support this
needs without bringing back the full `ECP_C`.
