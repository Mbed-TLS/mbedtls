Conditional inclusion of cryptographic mechanism through the PSA API in Mbed TLS
================================================================================

This document is a proposed interface for deciding at build time which cryptographic mechanisms to include in the PSA Cryptography interface.

This is currently a proposal for Mbed TLS. It is not currently on track for standardization in PSA.

Time-stamp: "2020/08/31 13:40:49 GMT"

## Introduction

### Purpose of this specification

The [PSA Cryptography API specification](https://armmbed.github.io/mbed-crypto/psa/#application-programming-interface) specifies the interface between a PSA Cryptography implementation and an application. The interface defines a number of categories of cryptographic algorithms (hashes, MAC, signatures, etc.). In each category, a typical implementation offers many algorithms (e.g. for signatures: RSA-PKCS#1v1.5, RSA-PSS, ECDSA). When building the implementation for a specific use case, it is often desirable to include only a subset of the available cryptographic mechanisms, primarily in order to reduce the code footprint of the compiled system.

The present document proposes a way for an application using the PSA cryptography interface to declare which mechanisms it requires.

### Current situation

Mbed TLS offers a way to select which cryptographic mechanisms are included in a build through its configuration file (`config.h`). This mechanism is based on two main sets of symbols: `MBEDTLS_xxx_C` controls the availability of the mechanism to the application, and `MBEDTLS_xxx_ALT` controls the availability of an alternative implementation, so the software implementation is only included if ``MBEDTLS_xxx_C` is defined but not `MBEDTLS_xxx_ALT`.

This is difficult to adapt to the PSA interface for several reasons. The `MBEDTLS_xxx_ALT` symbols are somewhat inconsistent, and in particular do not work well for asymmetric cryptography. For example, many parts of the ECC code have no `MBEDTLS_xxx_ALT` symbol, so a platform with ECC acceleration that can perform all ECDSA and ECDH operations in the accelerator would still embark the `bignum` module and large parts of the `ecp_curves`, `ecp` and `ecdsa` modules. Also the availability of a transparent driver for a mechanism does not translate directly to `MBEDTLS_xxx` symbols.

### Requirements

[Req.interface] The application can declare which cryptographic mechanisms it needs.

[Req.inclusion] If the application does not require a mechanism, a suitably configured Mbed TLS build must not include it. The granularity of mechanisms must work for typical use cases and has [acceptable limitations](#acceptable-limitations).

[Req.drivers] If a PSA driver is available in the build, a suitably configured Mbed TLS build must not include the corresponding software code (unless a software fallback is needed).

[Req.c] The configuration mechanism consists of C preprocessor definitions, and the build does not require tools other than a C compiler. This is necessary to allow building an application and Mbed TLS in development environments that do not allow third-party tools.

[Req.adaptability] The implementation of the mechanism must be adaptable with future evolution of the PSA cryptography specifications and Mbed TLS. Therefore the interface must remain sufficiently simple and abstract.

### Acceptable limitations

[Limitation.matrix] If a mechanism is defined by a combination of algorithms and key types, for example a block cipher mode (CBC, CTR, CFB, …) and a block permutation (AES, CAMELLIA, ARIA, …), there is no requirement to include only specific combinations.

[Limitation.direction] For mechanisms that have multiple directions (for example encrypt/decrypt, sign/verify), there is no requirement to include only one direction.

[Limitation.size] There is no requirement to include only support for certain key sizes.

[Limitation.multipart] Where there are multiple ways to perform an operation, for example single-part and multi-part, there is no mechanism to select only one or a subset of the possible ways.

## Interface

### PSA Crypto configuration file

The PSA crypto configuration file `psa/crypto_config.h` defines a series of symbols of the form `PSA_WANT_xxx` where `xxx` . The symbols are documented in the section [“PSA Crypto configuration symbols”](#psa-crypto-configuration-symbols) below.

The symbol `MBEDTLS_PSA_CRYPTO_CONFIG` in `mbedtls/config.h` determines whether `psa/crypto_config.h`. is used.

* If `MBEDTLS_PSA_CRYPTO_CONFIG` is unset, which is the default at least in Mbed TLS 2.x versions, things are as they are today: the PSA subsystem includes generic code unconditionally, and includes support for specific mechanisms conditionally based on the existing `MBEDTLS_xxx_` symbols.
* If `MBEDTLS_PSA_CRYPTO_CONFIG` is set, the necessary software implementations of cryptographic algorithms are included based on both the content of the PSA crypto configuration file and the Mbed TLS configuration file. For example, the code in `aes.c` is enabled if either `mbedtls/config.h` contains `MBEDTLS_AES_C` or `psa/crypto_config.h` contains `PSA_WANT_KEY_TYPE_AES`.

### PSA Crypto configuration symbols

#### Configuration symbol syntax

A PSA crypto configuration symbol is a C preprocessor symbol whose name starts with `PSA_WANT_`.

* If the symbol is not defined, the corresponding feature is not included.
* If the symbol is defined to a preprocessor expression with the value `1`, the corresponding feature is included.
* If the symbol is defined with a different value, the behavior is currently undefined and reserved for future use.

#### Configuration symbol semantics

If a feature is not requested for inclusion in the PSA crypto configuration file, it may still be included in the build, either because the feature has been requested in some other way, or because the library does not support the exclusion of this feature. Mbed TLS should make a best effort to support the exclusion of all features, but in some cases this may be judged too much effort for too little benefit.

#### Configuration symbols for key types

For each constant or constructor macro of the form `PSA_KEY_TYPE_xxx`, the symbol **`PSA_WANT_KEY_TYPE_xxx`** indicates that support for this key type is desired.

For asymmetric cryptography, `PSA_WANT_KEY_TYPE_xxx_KEY_PAIR` determines whether private-key operations are desired, and `PSA_WANT_KEY_TYPE_xxx_PUBLIC_KEY` determines whether public-key operations are desired. `PSA_WANT_KEY_TYPE_xxx_KEY_PAIR` implicitly enables `PSA_WANT_KEY_TYPE_xxx_PUBLIC_KEY`: there is no way to only include private-key operations (which typically saves little code).

#### Configuration symbols for curves

For elliptic curve key types, only the specified curves are included. To include a curve, include a symbol of the form **`PSA_WANT_ECC_family_size`**. For example: `PSA_WANT_ECC_SECP_R1_256` for secp256r1, `PSA_WANT_ECC_MONTGOMERY_CURVE25519`. It is an error to require an ECC key type but no curve, and Mbed TLS will reject this at compile time.

#### Configuration symbols for algorithms

For each constant or constructor macro of the form `PSA_ALG_xxx`, the symbol **`PSA_WANT_ALG_xxx`** indicates that support for this algorithm is desired.

For parametrized algorithms, the `PSA_WANT_ALG_xxx` symbol indicates whether the base mechanism is supported. Parameters must themselves be included through their own `PSA_WANT_ALG_xxx` symbols. It is an error to include a base mechanism without at least one possible parameter, and Mbed TLS will reject this at compile time. For example, `PSA_WANT_ALG_ECDSA` requires the inclusion of randomized ECDSA for all hash algorithms whose corresponding symbol `PSA_WANT_ALG_xxx` is enabled.

## Implementation

## Open questions

### Open questions about the interface

#### Naming of symbols

The names of [elliptic curve symbols](#configuration-symbols-for-curves) are a bit weird: `SECP_R1_256` instead of `SECP256R1`. Should we make them more classical, but less systematic?

#### Diffie-Hellman

Way to request only specific groups? Not a priority: constrained devices don't do FFDH. Specify it as may change in future versions.

#### Coexistence with the current Mbed TLS configuration

The two mechanisms have very different designs. Is there serious potential for confusion? Do we understand how the combinations work?

### Open questions about the design

#### Algorithms without a key type or vice versa

Is it realistic to mandate a compile-time error if a key type is required, but no matching algorithm, or vice versa? Is it always the right thing, for example if there is an opaque driver that manipulates this key type?

#### Opaque-only mechanisms

If a mechanism should only be supported in an opaque driver, what does the core need to know about it? Do we have all the information we need?

This is especially relevant to suppress a mechanism completely if there is no matching algorithm. For example, if there is no transparent implementation of RSA or ECDSA, `psa_sign_hash` and `psa_verify_hash` may still be needed if there is an opaque signature driver.

### Open questions about the implementation

#### Testability

Is this proposal decently testable? There are a lot of combinations. What combinations should we test?

<!--
Local Variables:
time-stamp-line-limit: 40
time-stamp-start: "Time-stamp: *\""
time-stamp-end: "\""
time-stamp-format: "%04Y/%02m/%02d %02H:%02M:%02S %Z"
time-stamp-time-zone: "GMT"
End:
-->
