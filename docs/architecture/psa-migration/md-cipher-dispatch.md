PSA migration strategy for hashes and ciphers
=============================================

## Introduction

This document discusses a migration strategy for code that is not subject to `MBEDTLS_USE_PSA_CRYPTO`, is currently using legacy cryptography APIs, and should transition to PSA, without a major version change.

### Relationship with the main strategy document

This is complementary to the main [strategy document](strategy.html) and is intended as a refinement. However, at this stage, there may be contradictions between the strategy proposed here and some of the earlier strategy.

A difference between the original strategy and the current one is that in this work, we are not treating PSA as a black box. We can change experimental features, and we can call internal interfaces.

## Requirements

### User stories

#### Backward compatibility user story

As a developer of an application that uses Mbed TLS's interfaces (including legacy crypto),  
I want Mbed TLS to preserve backward compatibility,  
so that my code keeps working in new minor versions of Mbed TLS.

#### Interface design user story

As a developer of library code that uses Mbed TLS to perform cryptographic operations,  
I want to know which functions to call and which feature macros to check,  
so that my code works in all Mbed TLS configurations.

Note: this is the same problem we face in X.509 and TLS.

#### Hardware accelerator vendor user stories

As a vendor of a platform with hardware acceleration for some crypto,  
I want to build Mbed TLS which uses my hardware wherever relevant,  
so that my customers maximally benefit from my hardware.

As a vendor of a platform with hardware acceleration for some crypto,  
I want to build Mbed TLS without software that replicates what my hardware does,  
to minimize the code size.

#### Maintainer user stories

As a maintainer of Mbed TLS,  
I want to have clear rules for when to use which interface,  
to avoid bugs in “unusual” configurations.

As a maintainer of Mbed TLS,  
I want to avoid duplicating code,  
because this is inefficient and error-prone.

### Use PSA more

In the long term, all code using cryptography should use PSA interfaces, to benefit from PSA drivers, allow eliminating legacy interfaces (less code size, less maintenance). However, this can't be done without breaking [backward compatibility](#backward-compatibility).

The goal of this work is to arrange for more non-PSA interfaces to use PSA interfaces under the hood, without breaking code in the cases where this doesn't work. Using PSA interfaces has two benefits:

* Where a PSA driver is available, it likely has better performance, and sometimes better security, than the built-in software implementation.
* In many scenarios, where a PSA driver is available, this allows removing the software implementation altogether.
* We may be able to get rid of some redundancies, for example the duplication between the implementations of HMAC in `md.c` and in `psa_crypto_mac.c`, and HKDF in `hkdf.c` and `psa_crypto.c`.

### Correct dependencies

Traditionally, to determine whether a cryptographic mechanism was available, you had to check whether the corresponding Mbed TLS module or submodule was present: `MBEDTLS_SHA256_C` for SHA256, `MBEDTLS_AES_C && MBEDTLS_CIPHER_MODE_CBC` for AES-CBC, etc. In code that uses the PSA interfaces, this needs to change to `PSA_WANT_xxx` symbols.

### Backward compatibility

All documented behavior must be preserved, except for interfaces currently described as experimental or unstable. Those interfaces can change, but we should minimize disruption by providing a transition path for reasonable use cases.

#### Changeable configuration options

The following configuration options are described as experimental, and are likely to change at least marginally:

* `MBEDTLS_PSA_CRYPTO_CLIENT`: “This interface is experimental and may change or be removed without notice.” In practice we don't want to remove this, but we may constrain how it's used.
* `MBEDTLS_PSA_CRYPTO_DRIVERS`: “This interface is experimental. We intend to maintain backward compatibility with application code that relies on drivers, but the driver interfaces may change without notice.” In practice, this may mean constraints not only on how to write drivers, but also on how to integrate drivers into code that is platform code more than application code.

### Non-goals

It is not a goal at this stage to make more code directly call `psa_xxx` functions. Rather, the goal is to make more code call PSA drivers where available. How dispatch is done is secondary.

## Problem analysis

### Scope analysis

#### Limitations of `MBEDTLS_USE_PSA_CRYPTO`

`MBEDTLS_USE_PSA_CRYPTO` only applies to `pk.h`, X.509 and TLS. When this option is enabled, applications must call `psa_crypto_init()` before calling any of the functions in these modules.

In this work, we want two things:

* Partially apply `MBEDTLS_USE_PSA_CRYPTO` to non-covered modules, but only [when this will actually work](#why-psa-is-not-always-possible).
* Effectively apply `MBEDTLS_USE_PSA_CRYPTO` when a covered module calls a non-covered module which calls another module, for example X.509 calling pk for PSS verification which calls RSA which calculates a hash ([see issue \#6497](https://github.com/Mbed-TLS/mbedtls/issues/6497)).

#### Classification of callers

We can classify code that implements or uses cryptographic mechanisms into several groups:

* Software implementations of primitive cryptographic mechanisms. These are not expected to change.
* Software implementations of constructed cryptographic mechanisms (e.g. HMAC, CTR_DRBG, RSA (calling a hash for PSS/OAEP), …). These need to keep working whenever a legacy implementation of the auxiliary mechanism is available, even if a PSA implementation is also available.
* Code implementing the PSA crypto interface. This is not expected to change, except perhaps to expose some internal functionality to overhauled glue code.
* Code that's subject to `MBEDTLS_USE_PSA_CRYPTO`: `pk.h`, X.509, TLS (excluding TLS 1.3).
* Code that always uses PSA for crypto: TLS 1.3, LMS.

For the purposes of this work, three domains emerge:

* **Legacy domain**: does not interact with PSA. Implementations of hashes, of cipher primitives, of arithmetic.
* **Mixed domain**: does not currently use PSA, but should [when possible](#why-psa-is-not-always-possible). This consists of the constructed cryptographic primitives (except LMS), as well as pk, X.509 and TLS when `MBEDTLS_USE_PSA_CRYPTO` is disabled.
* **PSA domain**: includes pk, X.509 and TLS when `MBEDTLS_USE_PSA_CRYPTO` is enabled. Also TLS 1.3, LMS.

#### Non-use-PSA modules

The following modules in Mbed TLS call another module to perform cryptographic operations which, in the long term, will be provided through a PSA interface, but cannot make any PSA-related assumption:

* CCM (block cipher in ECB mode; interdependent with cipher)
* cipher (cipher and AEAD algorithms)
* CMAC (AES-ECB and DES-ECB, but could be extended to the other block ciphers; interdependent with cipher)
* CTR\_DRBG (AES-ECB, but could be extended to the other block ciphers)
* entropy (hashes via low-level)
* ECDSA (hashes via md; `md.h` exposed through API)
* ECJPAKE (HMAC\_DRBG; `md.h` exposed through API)
* GCM (block cipher in ECB mode; interdependent with cipher)
* md (hashes and HMAC)
* NIST\_KW (AES-ECB; interdependent with cipher)
* HMAC\_DRBG (hashes and HMAC via `md.h`; `md.h` exposed through API)
* PEM (AES and DES in CBC mode without padding; MD5 hash via low-level)
* PKCS12 (cipher, generically, selected from ASN.1 or function parameters; hashes via md; `cipher.h` exposed through API)
* PKCS5 (cipher, generically, selected from ASN.1; HMAC via `md.h`; `md.h` exposed through API)
* RSA (hash via md for PSS and OAEP; `md.h` exposed through API)

### Difficulties

#### Why PSA is not always possible

Here are some reasons why calling `psa_xxx()` to perform a hash or cipher calculation might not be desirable in some circumstances, explaining why the application would arrange to call the legacy software implementation instead.

* `MBEDTLS_PSA_CRYPTO_C` is disabled.
* There is a PSA driver which has not been initialized (this happens in `psa_crypto_init()`).
* The requested mechanism is enabled in the legacy interface but not in the PSA interface. This was not really intended, but is possible, for example, if you enable `MBEDTLS_MD5_C` for PEM decoding with PBKDF1 but don't want `PSA_ALG_WANT_MD5` because it isn't supported for `PSA_ALG_RSA_PSS` and `PSA_ALG_DETERMINISTIC_ECDSA`.
* `MBEDTLS_PSA_CRYPTO_CLIENT` is enabled, and the client has not yet activated the connection to the server (this happens in `psa_crypto_init()`).
* `MBEDTLS_PSA_CRYPTO_CLIENT` is enabled, but the local implementation is faster because it avoids a remote procedure call.

#### Indirect knowledge

Consider for example the code in `rsa.c` to perform an RSA-PSS signature. It needs to calculate a hash. If `mbedtls_rsa_rsassa_pss_sign()` is called directly by application code, it is supposed to call the built-in implementation: calling a PSA accelerator would be a behavior change, acceptable only if this does not add a risk of failure or performance degradation ([PSA is impossible or undesirable in some circumstances](#why-psa-is-not-always-possible)). Note that this holds regardless of the state of `MBEDTLS_USE_PSA_CRYPTO`, since `rsa.h` is outside the scopre of `MBEDTLS_USE_PSA_CRYPTO`. On the other hand, if `mbedtls_rsa_rsassa_pss_sign()` is called from X.509 code, it should use PSA to calculate hashes. It doesn't, currently, which is [bug \#6497](https://github.com/Mbed-TLS/mbedtls/issues/6497).

Generally speaking, modules in the mixed domain:

* must call PSA if called by a module in the PSA domain;
* must not call PSA (or must have a fallback) if their caller is not in the PSA domain and the PSA call is not guaranteed to work.

