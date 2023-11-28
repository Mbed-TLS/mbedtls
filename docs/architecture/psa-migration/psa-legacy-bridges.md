Bridges between legacy and PSA crypto APIs
==========================================

## Introduction

### Goal of this document

This document explores the needs of applications that use both Mbed TLS legacy crypto interfaces and PSA crypto interfaces. Based on [requirements](#requirements), we [analyze gaps](#gap-analysis) and [API design](#api-design).

This is a design document. The target audience is library maintainers. See the companion document [“Transitioning to the PSA API”](../../psa-transition.md) for a user focus on the same topic.

### Keywords

* [TODO] A part of the analysis that isn't finished.
* [QUESTION] A specific aspect of the design where there are several plausible decisions.
* [ACTION] A finalized part of the design that will need to be carried out.

### Context

Mbed TLS 3.x supports two cryptographic APIs:

* The legacy API `mbedtls_xxx` is inherited from PolarSSL.
* The PSA API `psa_xxx` was introduced in Mbed TLS 2.17.

Mbed TLS is gradually shifting from the legacy API to the PSA API. Mbed TLS 4.0 will be the first version where the PSA API is considered the main API, and large parts of the legacy API will be removed.

In Mbed TLS 4.0, the cryptography will be provided by a separate project [TF-PSA-Crypto](https://github.com/Mbed-TLS/TF-PSA-Crypto). For simplicity, in this document, we just refer to the whole as “Mbed TLS”.

### Document history

This document was originally written when preparing Mbed TLS 3.6. Mbed TLS 3.6 includes both PSA and legacy APIs covering largely overlapping ground. Many legacy APIs will be removed in Mbed TLS 4.0.

## Requirements

### Why mix APIs?

There is functionality that is tied to one API and is not directly available in the other API:

* Only PSA fully supports PSA accelerators and secure element integration.
* Only PSA supports isolating cryptographic material in a secure service.
* The legacy API has features that are not present (yet) in PSA, notably parsing and formatting asymmetric keys.

The legacy API can partially leverage PSA features via `MBEDTLS_USE_PSA_CRYPTO`, but this has limited scope.

In addition, many applications cannot be migrated in a single go. For large projects, it is impractical to rewrite a significant part of the code all at once. (For example, Mbed TLS itself will have taken more than 6 years to transition.) Projects that use one or more library in addition to Mbed TLS must follow the evolution of these libraries, each of which might have its own pace.

### Where mixing happens

Mbed TLS can be, and normally is, built with support for both APIs. Therefore no special effort is necessary to allow an application to use both APIs.

Special effort is necessary to use both APIs as part of the implementation of the same feature. From an informal analysis of typical application requirements, we identify four parts of the use of cryptography which can be provided by different APIs:

* Metadata manipulation: parsing and producing encrypted or signed files, finding mutually supported algorithms in a network protocol negotiation, etc.
* Key management: parsing, generating, deriving and formatting cryptographic keys.
* Data manipulation other than keys. In practice, most data formats within the scope of the legacy crypto APIs are trivial (ciphertexts, hashes, MACs, shared secrets). The one exception is ECDSA signatures.
* Cryptographic operations: hash, sign, encrypt, etc.

From this, we deduce the following requirements:

* Convert between PSA and legacy metadata.
* Creating a key with the legacy API and consuming it in the PSA API.
* Creating a key with the PSA API and consuming it in the legacy API.
* Manipulating data formats, other than keys, where the PSA API is lacking.

### Scope limitations

The goal of this document is to bridge the legacy API and the PSA API. The goal is not to provide a PSA way to do everything that is currently possible with the legacy API. The PSA API is less flexible in some regards, and extending it is out of scope in the present study.

With respect to the legacy API, we do not consider functionality of low-level modules for individual algorithms. Our focus is on applications that use high-level legacy crypto modules (md, cipher, pk) and need to combine that with uses of the PSA APIs.

## Gap analysis

Based on “[Where mixing happens](#where-mixing-happens)”, we focus the gap analysis on two topics: metadata and keys. This chapter explores the gaps in each family of cryptographic mechanisms.

### Generic metadata gaps

#### Need for error code conversion

[QUESTION] Do we need public functions to convert between `MBEDTLS_ERR_xxx` error codes and `PSA_ERROR_xxx` error codes? We have such functions for internal use.

### Hash gap analysis

Hashes do not involve keys, and involves no nontrivial data format. Therefore the only gap is with metadata, namely specifying a hash algorithm.

Hashes are often used as building blocks for other mechanisms (HMAC, signatures, key derivation, etc.). Therefore metadata about hashes is relevant not only when calculating hashes, but also when performing many other cryptographic operations.

Gap: functions to convert between `psa_algorithm_t` hash algorithms and `mbedtls_md_type_t`. Such functions exist in Mbed TLS 3.5 (`mbedtls_md_psa_alg_from_type`, `mbedtls_md_type_from_psa_alg`) but they are declared only in private headers.

### MAC gap analysis

[TODO]

### Cipher and AEAD gap analysis

[TODO]

### Key derivation gap analysis

[TODO]

### Random generation gap analysis

[TODO]

### Asymmetric cryptography gap analysis

[TODO]

## New APIs

This section presents new APIs to implement based on the [gap analysis](#gap-analysis).

### Hash APIs

Based on the [gap analysis](#hash-gap-analysis):

[ACTION] Move `mbedtls_md_psa_alg_from_type` and `mbedtls_md_type_from_psa_alg` from `library/md_psa.h` to `include/mbedtls/md.h`.

### MAC APIs

[TODO]

### Cipher and AEAD APIs

[TODO]

### Key derivation APIs

[TODO]

### Random generation APIs

[TODO]

### Asymmetric cryptography APIs

[TODO]
