The pk module in TF-PSA-Crypto 1 and Mbed TLS 4
===============================================

The goal of this document is to describe the evolution of the `pk.h` interface from Mbed TLS 3.x going into TF-PSA-Crypto 1.0 and Mbed TLS 4.0.

## High-level requirements

### Should it stay or should it go?

We would like TF-PSA-Crypto to focus on PSA cryptography APIs. `pk.h` is a legacy cryptography API, so ideally it should be removed.

However, there is functionality in pk that does not exist yet in PSA:

* The ability to parse a key in various commonplace formats. These formats include metadata indicating the key type, so this cannot be a simple extension of `psa_import_key`.
* The ability to write a key in various commonplace formats.
* The ability to manipulate a key independently of a PSA backing. This matters for resource management: a pk object uses space on the local heap (or possibly on the stack), while a PSA key object uses space in the crypto service which may be separate from the application.
* A signature format that's ready for X.509 and TLS.

The PSA Crypto working group is working on new APIs for key parsing and formatting, but they are not ready yet at the time we want to start working on the new pk. We prefer not to wait for these APIs to avoid risk: both the risk that they will be finalized too late, and the risk that we would have to be beta implementers and we would have to freeze the API for our release without having it field-tested, requiring us to wait for TF-PSA-Crypto 2.0 to provide the actual final API.

In addition, many X.509 API types contain embedded `mbedtls_pk_context` objects. It is less work for us to prepare Mbed TLS 4.0 if we can continue using these objects and the main functions that operate on these objects.

For these reasons, we will keep a `pk.h` which is close to the existing one. We will however make incompatible changes where they are helpful.

### Main design goals

Our main goals for the evolution of `pk.h` are:

* Smoothen compatibility with PSA, based on lessons learned from the PSA-PK bridge added in Mbed TLS 3.5.0.
* Support the needs of X.509 and TLS code.
* Support parsing and formatting keys.
* Accommodate current key types (RSA, ECC). EdDSA is close enough to ECDSA that it should work as well. If we can later accommodate post-quantum keys, that's nice, but we aren't going to go out of our way to cater for PQC in 4.0.
* Remove functionality that we no longer care about.
* Avoid breaking existing code for no good reason.

Therefore our guidelines for how to evolve `pk.h` will be:

* If it isn't relevant in a PSA-centric world, or if it isn't useful for X.509 and similar use cases, remove it.
* If the functionality is relevant but the current interface clashes with PSA, change the interface to be more compatible with PSA.
* If an application would typically want to bridge some pk functionality with some PSA functionality, make sure that there are ways to do it. This already exists since Mbed TLS 3.5 but will need to be checked and revised for the redesigned API.
* If it isn't broken or useless, don't change it.
* If it works but is hard to use or inefficient, decide on a case-by-case basis.



## A study of pk in Mbed TLS 3

### Functionality of pk in Mbed TLS 3.6

#### Old type and policy

```
typedef enum {
    MBEDTLS_PK_NONE=0,
    MBEDTLS_PK_RSA,
    MBEDTLS_PK_ECKEY,
    MBEDTLS_PK_ECKEY_DH,
    MBEDTLS_PK_ECDSA,
    MBEDTLS_PK_RSA_ALT,
    MBEDTLS_PK_RSASSA_PSS,
    MBEDTLS_PK_OPAQUE,
} mbedtls_pk_type_t;
mbedtls_pk_type_t mbedtls_pk_get_type(const mbedtls_pk_context *ctx);
int mbedtls_pk_can_do(const mbedtls_pk_context *ctx, mbedtls_pk_type_t type);
```

The historical `mbedtls_pk_type_t` is an awkward mixture of multiple considerations:

* The key type (EC vs RSA).
* The key policy (RSA-unspecified vs RSA-PSS; EC-unspecified vs EC-DH vs EC-DSA).
* The backend that operates on the key (transparent vs RSA-ALT vs opaque).

See [“Old PK context constructions”](#old-pk-object-constructions) for how objects of these types are constructed.

Even before PSA came into play, we were unhappy with this mixture of concerns. PSA has separate metadata indications for these three concerns.

Verdict: remove `mbedtls_pk_type_t`. Use PSA types as much as possible. Reintroduce a PK-specific metadata type only if we really have to.

#### Old metatada functions

```
int mbedtls_pk_can_do_ext(const mbedtls_pk_context *ctx, psa_algorithm_t alg,
                          psa_key_usage_t usage);
size_t mbedtls_pk_get_bitlen(const mbedtls_pk_context *ctx);
size_t mbedtls_pk_get_len(const mbedtls_pk_context *ctx);
const char *mbedtls_pk_get_name(const mbedtls_pk_context *ctx);
```

There's nothing wrong with `mbedtls_pk_can_do_ext` and `mbedtls_pk_get_bitlen`, and they aren't difficult to implement. So keep them.

`mbedtls_pk_get_len` is basically useless. It dates back from the days of RSA only, and doesn't make sense with Weierstrass curve ECC keys. Remove it.

Remove `mbedtls_pk_get_name`. We don't expose custom names for algorithms these days.

#### Old PK info

```
typedef struct mbedtls_pk_info_t mbedtls_pk_info_t;
const mbedtls_pk_info_t *mbedtls_pk_info_from_type(mbedtls_pk_type_t pk_type);
```

The old API has a level of indirection between `mbedtls_pk_type_t` (enum describing a type/policy combination) and `mbedtls_pk_info_t` (class vtable for the type/policy combination). No remaining function needs to expose `mbedtls_pk_info_t`.

Verdict: remove.

#### Old PK context

```
typedef ... mbedtls_pk_context;
void mbedtls_pk_init(mbedtls_pk_context *ctx);
void mbedtls_pk_free(mbedtls_pk_context *ctx);
```

We'll keep the context type. There's no reason to change it. Of course the content of the structure will change.

#### Old low-level context access

```
int mbedtls_pk_setup(mbedtls_pk_context *ctx, const mbedtls_pk_info_t *info);
mbedtls_rsa_context *mbedtls_pk_rsa(const mbedtls_pk_context pk);
mbedtls_ecp_keypair *mbedtls_pk_ec(const mbedtls_pk_context pk);
```

These functions allow constructing and inspecting a PK context containing a transparent key. They are already informally deprecated and fundamentally incompatible with PSA.

Verdict: remove.

#### Old signature

```
#define MBEDTLS_PK_SIGNATURE_MAX_SIZE ...
int mbedtls_pk_verify(mbedtls_pk_context *ctx, mbedtls_md_type_t md_alg,
                      const unsigned char *hash, size_t hash_len,
                      const unsigned char *sig, size_t sig_len);
int mbedtls_pk_sign(mbedtls_pk_context *ctx, mbedtls_md_type_t md_alg,
                    const unsigned char *hash, size_t hash_len,
                    unsigned char *sig, size_t sig_size, size_t *sig_len,
                    int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);
```

#### Old RSA-PSS support

```
typedef struct mbedtls_pk_rsassa_pss_options {
    mbedtls_md_type_t mgf1_hash_id;
    int expected_salt_len;
} mbedtls_pk_rsassa_pss_options;
int mbedtls_pk_verify_ext(mbedtls_pk_type_t type, const void *options,
                          mbedtls_pk_context *ctx, mbedtls_md_type_t md_alg,
                          const unsigned char *hash, size_t hash_len,
                          const unsigned char *sig, size_t sig_len);
int mbedtls_pk_sign_ext(mbedtls_pk_type_t pk_type,
                        mbedtls_pk_context *ctx,
                        mbedtls_md_type_t md_alg,
                        const unsigned char *hash, size_t hash_len,
                        unsigned char *sig, size_t sig_size, size_t *sig_len,
                        int (*f_rng)(void *, unsigned char *, size_t),
                        void *p_rng);
```

This is an extended signature interface meant for RSA-PSS signatures. When verifying, it allows specifying a different hash for the MGF+salt and for the message, and the expected salt length. When signing, it allows forcing PSS with a key that isn't configured for PSS, but the hash and salt length will be the default unless the key has been configured for PSS.

Verdict: remove. If the PSA API doesn't give us enough flexibility for the needs of X.509 (or third-party users), we'll extend the PSA API.

#### Old restartable signature

```
typedef ... mbedtls_pk_restart_ctx;
void mbedtls_pk_restart_init(mbedtls_pk_restart_ctx *ctx);
void mbedtls_pk_restart_free(mbedtls_pk_restart_ctx *ctx);
int mbedtls_pk_verify_restartable(mbedtls_pk_context *ctx,
                                  mbedtls_md_type_t md_alg,
                                  const unsigned char *hash, size_t hash_len,
                                  const unsigned char *sig, size_t sig_len,
                                  mbedtls_pk_restart_ctx *rs_ctx);
int mbedtls_pk_sign_restartable(mbedtls_pk_context *ctx,
                                mbedtls_md_type_t md_alg,
                                const unsigned char *hash, size_t hash_len,
                                unsigned char *sig, size_t sig_size, size_t *sig_len,
                                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
                                mbedtls_pk_restart_ctx *rs_ctx);
```

Variants of the sign and verify functions that should be called in a loop while they return `MBEDTLS_ERR_ECP_IN_PROGRESS`.

Useful functionality, but this can also be done via the PSA API. Keep or remove depending on what's most convenient for us considering PK+X509+TLS as a whole.

#### Old encryption

```
int mbedtls_pk_decrypt(mbedtls_pk_context *ctx,
                       const unsigned char *input, size_t ilen,
                       unsigned char *output, size_t *olen, size_t osize,
                       int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);
int mbedtls_pk_encrypt(mbedtls_pk_context *ctx,
                       const unsigned char *input, size_t ilen,
                       unsigned char *output, size_t *olen, size_t osize,
                       int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);
```

Encryption is now only supported for a single algorithm: RSA-OAEP. It isn't used in TLS anymore. We don't need an abstraction for it.

Verdict: remove.

#### Old bridges from PSA

```
int mbedtls_pk_setup_opaque(mbedtls_pk_context *ctx,
                            const mbedtls_svc_key_id_t key);
int mbedtls_pk_copy_from_psa(mbedtls_svc_key_id_t key_id, mbedtls_pk_context *pk);
int mbedtls_pk_copy_public_from_psa(mbedtls_svc_key_id_t key_id, mbedtls_pk_context *pk);
```

`mbedtls_pk_setup_opaque` wraps a PSA key as a PK context. `mbedtls_pk_copy_from_psa` and `mbedtls_pk_copy_public_from_psa` copies a PSA key as a PK context.

In a PSA-centric world, a PK context that is a wrapped PSA key is the normal thing. If the key was created by parsing, the PK context comes first, otherwise the PSA context comes first. Keeping `mbedtls_pk_setup_opaque` is very natural except for the name.

The copy functions are less useful, but already implemented and not costly to maintain, and having them facilitates the transition for applications that maintain 3.6/4.x compatibility for a while.

Verdict: keep. Perhaps give `mbedtls_pk_setup_opaque` a new name.

#### Old bridge to PSA

```
int mbedtls_pk_get_psa_attributes(const mbedtls_pk_context *pk,
                                  psa_key_usage_t usage,
                                  psa_key_attributes_t *attributes);
int mbedtls_pk_import_into_psa(const mbedtls_pk_context *pk,
                               const psa_key_attributes_t *attributes,
                               mbedtls_svc_key_id_t *key_id);
```

This pair of functions (meant to be used together) allows applications to create a PSA key from a PK context. The design is intended for a three-step process to create a PSA key:

1. The library parses a key of unknown type.
2. Now that the key type is known, the application decides on the policy.
3. The library creates a key object with the given policy.

In a PSA-centric world, as soon as we parse a key, we need to give it a policy. The workflow above is quite natural, but is awkward to implement. Still, it _can_ be implemented: as long as step 1 creates an exportable PSA key, step 3 can copy it from outside PSA to create a new PSA object.

This is a somewhat inefficient workflow, but it's already implemented and not costly to maintain.

Verdict: keep, even though a better alternative would be nice.

#### Old parsing and writing functions

```
int mbedtls_pk_parse_key(mbedtls_pk_context *ctx,
                         const unsigned char *key, size_t keylen,
                         const unsigned char *pwd, size_t pwdlen,
                         int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);
int mbedtls_pk_parse_public_key(mbedtls_pk_context *ctx,
                                const unsigned char *key, size_t keylen);
int mbedtls_pk_parse_keyfile(mbedtls_pk_context *ctx,
                             const char *path, const char *password,
                             int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);
int mbedtls_pk_parse_public_keyfile(mbedtls_pk_context *ctx, const char *path);
int mbedtls_pk_write_key_der(const mbedtls_pk_context *ctx, unsigned char *buf, size_t size);
int mbedtls_pk_write_pubkey_der(const mbedtls_pk_context *ctx, unsigned char *buf, size_t size);
int mbedtls_pk_write_pubkey_pem(const mbedtls_pk_context *ctx, unsigned char *buf, size_t size);
int mbedtls_pk_write_key_pem(const mbedtls_pk_context *ctx, unsigned char *buf, size_t size);
int mbedtls_pk_parse_subpubkey(unsigned char **p, const unsigned char *end,
                               mbedtls_pk_context *pk);
int mbedtls_pk_write_pubkey(unsigned char **p, unsigned char *start,
                            const mbedtls_pk_context *key);
```

Parsing and writing functions have no PSA equivalent.

We will keep at least some of these functions. Preferably we should keep them as they are, to minimize code changes. Open questions:

* Do we keep file parsing/writing?
* `mbedtls_pk_parse_subpubkey` and `mbedtls_pk_write_pubkey` are part of the documented API, but a comment in the code says “Low-level functions. You probably do not want to use these unless you are certain you do”. Do we keep them as a documented API? They are needed for X.509.
* What policy will parsing apply to the created key?

#### Old check pair

```
int mbedtls_pk_check_pair(const mbedtls_pk_context *pub,
                          const mbedtls_pk_context *prv,
                          int (*f_rng)(void *, unsigned char *, size_t),
                          void *p_rng);
```

Check whether a given public key matches a given private key. We don't use this elsewhere in the library, but we use it in sample code. It's easy to implement.

Verdict: keep.

#### Old debug

```
typedef ... mbedtls_pk_debug_type;
typedef ... mbedtls_pk_debug_item;
#define MBEDTLS_PK_DEBUG_MAX_ITEMS ...
int mbedtls_pk_debug(const mbedtls_pk_context *ctx, mbedtls_pk_debug_item *items);
```

A way to extract some information about a key in a poorly documented format that's tied to the low-level data representation. Not used by X.509/TLS except for debugging in a way that can be easily replaced ([Task: debug removal](#task-debug-removal)). Doesn't look very useful. Hard to reconcile with PSA.

Verdict: remove.

#### Old RSA-ALT

```
typedef int (*mbedtls_pk_rsa_alt_decrypt_func)(...);
typedef int (*mbedtls_pk_rsa_alt_sign_func)(...);
typedef size_t (*mbedtls_pk_rsa_alt_key_len_func)(...);
int mbedtls_pk_setup_rsa_alt(mbedtls_pk_context *ctx, void *key,
                             mbedtls_pk_rsa_alt_decrypt_func decrypt_func,
                             mbedtls_pk_rsa_alt_sign_func sign_func,
                             mbedtls_pk_rsa_alt_key_len_func key_len_func);
```

Superseded by PSA drivers.

Verdict: remove.

### How PK types are used

#### Old PK context constructions

Mbed TLS 3.6 offers the following ways to create PK objects:

* `mbedtls_pk_setup` with one of the types `MBEDTLS_PK_RSA`, `MBEDTLS_PK_ECKEY`, `MBEDTLS_PK_ECKEY_DH` or `MBEDTLS_PK_ECDSA`; then retrieve a pointer to the underlying low-level context with `mbedtls_pk_rsa` or `mbedtls_pk_ec` and use RSA or ECP interfaces to populate the low-level context.
* `mbedtls_pk_setup_opaque` to create context of type `MBEDTLS_PK_OPAQUE` that wraps around a PSA private key.
* `mbedtls_pk_setup_rsa_alt` to create a context of type `MBEDTLS_PK_RSA_ALT`.
* Key parsing. This always creates a transparent key (not opaque or ALT). For RSA keys, the type is always `MBEDTLS_PK_RSA`. For elliptic curve keys, the type is `MBEDTLS_PK_ECKEY`, except that it's `MBEDTLS_PK_ECKEY_DH` if the key (public or private) has the OID `id-ecDH` (as opposed to `id-ecPublicKey` or a format with no OID).

Note that there are no PK contexts of type `MBEDTLS_PK_RSASSA_PSS`, and PK contexts of type `MBEDTLS_PK_ECDSA` can only be constructed manually.

### Uses of `mbedtls_pk_type_t` other than for `mbedtls_pk_context`

In the X.509 code, `mbedtls_x509_get_sig_alg` is used to populate the `sig_pk` field of CRT, CRL and CSR objects. Based on the OID in what is parsed, this can return values of any of the types `MBEDTLS_PK_RSA`, `MBEDTLS_PK_RSASSA_PSS`, `MBEDTLS_PK_ECKEY` or `MBEDTLS_PK_ECDSA` (but not `MBEDTLS_PK_ECKEY_DH`).

### Uses of pk going into TF-PSA-Crypto 1.0

In the part of Mbed TLS that is moving into TF-PSA-Crypto, `pk.h` is a root interface (no users), except that `oid.h` has OID lookup functions that use the type `mbedtls_pk_type_t`. The OID functions are for the sake of pk parsing and writing functions and X.509 writing functions. They are mainly for internal purposes and could conceptually be exposed by `pk.h` rather than `oid.h`. They are subject to the OID module redesign [#9380](https://github.com/Mbed-TLS/mbedtls/issues/9380).

### Uses of pk types in interfaces going into Mbed TLS 4.0

We look at uses of `pk.h` interfaces in Mbed TLS 3.6 X.509 and TLS interfaces, excluding any uses that will be removed due to `MBEDTLS_USE_PSA_CRYPTO` being always on.

#### Uses of `mbedtls_pk_type_t`

* Field of `mbedtls_x509_crl`: `sig_pk` (private).
* Field of `mbedtls_x509_crt`: `sig_pk` (private).
* Field of `mbedtls_x509_csr`: `sig_pk` (private).

All of them are for a signature algorithm (RSA-PKCS1v1.5, RSA-PSS or ECDSA).

#### Uses of `mbedtls_pk_context`

* Field of `mbedtls_x509_crt`: `pk` (public). Public key.
* Field of `mbedtls_x509_csr`: `pk` (public). Public key.
* Field of `mbedtls_x509write_cert`: `subject_key` (private). Public key.
* Field of `mbedtls_x509write_cert`: `issuer_key` (private). Private key.
* Field of `mbedtls_x509write_csr`: `key` (private). Private key.
* Input to `mbedtls_x509write_crt_set_subject_key()`. Public key.
* Input to `mbedtls_x509write_crt_set_issuer_key()`. Private key.
* Input to `mbedtls_x509write_csr_set_key()`. Private key.
* Input to `mbedtls_ssl_conf_own_cert()`, `mbedtls_ssl_set_hs_own_cert()`. Private key.

#### Uses of `mbedtls_pk_restart_ctx`

* Field of `mbedtls_x509_crt_restart_ctx`: `pk` (private). Public key.

### Calls to pk functions in modules going into Mbed TLS 4.0

We look at uses of `pk.h` and `pk_internal.h` interfaces (more precisely: `mbedtls_pk_xxx` function calls) in X.509 and TLS modules as of Mbed TLS 3.6.0.

We omit the following functions because they're staying and not informative:

* `mbedlts_pk_init`, `mbedtls_pk_free`
* `mbedtls_pk_restart_init`, `mbedtls_pk_restart_free`

Calls that are only made in a non-PSA build, for which a fully-PSA alternative code path exists, are listed for completeness, but in their own section [“Uses of functions in non-fully-PSA builds”](#uses-of-functions-in-non-fully-psa-builds).

#### Uses of `mbedtls_pk_can_do`

* Used in `x509_crt_check_signature` to “Skip expensive computation on obvious mismatch”. Though looking at the context I don't think this comment is accurate: without this, if a forgery is possible for `parent->pk` but not for `child->sig_pk`, wouldn't it open the door to a getting forged certificate accepted? Also, for ECC keys, can a non-ECDSA-authorized EC key get this far? TODO: figure out what check is actually called for here, then specify how to do it with PSA metadata.
* Used in `ssl_tls13_parse_certificate_verify` for TLS 1.3, to check whether the signature algorithm declared in the CertificateVerify message matches the signature algorithm in the certificate. It's not clear what to me what the impact of this verification is, same as in `x509_crt_check_signature`.
* Used in `mbedtls_x509write_crt_der` and `x509write_csr_der_internal` to decide between RSA and ECC to pick a signature algorithm OID.
* Used in `mbedtls_ssl_sig_from_pk` (called by both TLS 1.2 and TLS 1.3) to find which signature algorithm (RSA or ECC) corresponds to a key.
* Used in TLS 1.2 (`ssl_parse_certificate_verify`) to check that the peer key matches the signature algorithm in the CertificateVerify message.
* Used in TLS 1.2 (`ssl_parse_certificate_verify`) to determine whether the key is an EC key, in which case the code needs to check that the curve matches what is selected in the SSL context.
* Used in TLS 1.2 for RSA-encryption cipher suites to check that the key is indeed RSA (`ssl_write_encrypted_pms`, `ssl_decrypt_encrypted_pms`).
* Used in TLS 1.2 (`ssl_get_ecdh_params_from_cert`) for static ECDH to check that the key is an ECC key whose policy allows ECDH.
* Used in `ssl_parse_server_key_exchange`, for TLS 1.2, to check that the peer's public key has the right type (RSA or ECC) for the offered signature algorithm.

#### Uses of `mbedtls_pk_can_do_ext`

* Used in `ssl_pick_cert` for TLS 1.2, to check whether a key is suitable for a cipher suite (based on data in `mbedtls_ssl_ciphersuite_t`).
* Used in `mbedtls_ssl_tls12_get_preferred_hash_for_sig_alg` to determine whether a key's policy is compatible with a TLS signature algorithm.
* Used in `ssl_tls13_pick_cert` for TLS 1.3, to check whether a key is suitable for an offered signature algorithm. This is only when done `MBEDTLS_USE_PSA_CRYPTO` is enabled, otherwise the decision is based on the PK type.

#### Uses of `mbedtls_pk_debug`

Only in `debug.c`. See [Task: debug removal](#task-debug-removal).

#### Uses of `mbedtls_pk_encrypt` or `mbedtls_pk_encrypt`

* Used in TLS 1.2 for RSA-encryption cipher suites (`ssl_write_encrypted_pms`, `ssl_decrypt_encrypted_pms`).

#### Uses of `mbedtls_pk_get_bitlen`

* Used in `mbedtls_x509_crt_info`, `mbedtls_x509_csr_info`.
* Used in `x509_profile_check_key`.
* Used in `mbedtls_ssl_tls13_check_sig_alg_cert_key_match`.

#### Uses of `mbedtls_pk_get_len`

* Used in TLS 1.2 for RSA decryption (`ssl_decrypt_encrypted_pms`).

#### Uses of `mbedtls_pk_get_ec_group_id`

* Used in `x509_profile_check_key` to check against an X.509 certificate policy.
* Used in `ssl_parse_certificate_verify` to check that the curve matches what is selected in the SSL context.
* Used in `ssl_get_ecdh_params_from_cert` for static ECDH.
* Used in `ssl_check_key_curve` for ECDSA in TLS 1.2 servers.

#### Uses of `mbedtls_pk_get_name`

* Used in `mbedtls_x509_crt_info` and `mbedtls_x509_csr_info` to print output for human consumption.

#### Uses of `mbedtls_pk_get_type`

* Used in `x509_crt.c` to pass to `x509_profile_check_pk_alg` which calls `MBEDTLS_X509_ID_FLAG`. Certificate policies only need to distinguish ECC vs RSA: ECDH-only certificates shouldn't get that far.
  TODO: figure out how we're going to encode X.509 certificate policies in the new world. The current encoding relies on a value between 1 and 32 for RSA vs ECC, and another value between 1 and 32 for the elliptic curve. See [Task: test X.509 ID flags](task-test-x-509-id-flags).
* Used in `x509_profile_check_key` to check against an X.509 certificate policy.
* Used in TLS 1.2 (`ssl_get_ecdh_params_from_cert`) for static ECDH to check that the key is an ECC key whose policy allows ECDH.

#### Uses of `mbedtls_pk_load_file`

* Used in `mbedtls_x509_crl_parse_file`, `mbedtls_x509_crt_parse_file`, `mbedtls_x509_csr_parse_file`.

#### Uses of `mbedtls_pk_parse_key`, `mbedtls_pk_parse_public_key`,

#### Uses of `mbedtls_pk_parse_subpubkey`

* Used in certificate parsing (`x509_crt_parse_der_core`).
* Used in CSR parsing (`mbedtls_x509_csr_parse_der_internal`).
* Used in TLS (`ssl_remember_peer_pubkey` called by `mbedtls_ssl_parse_certificate`). (There may be another way to do this, but I don't see a compelling argument to change.)

#### Uses of `mbedtls_pk_sign`

* Used in certificate writing (`mbedtls_x509write_crt_der`).
* Used in CSR writing (`x509write_csr_der_internal`).
* Used in TLS 1.2 (`ssl_prepare_server_key_exchange`).

#### Uses of `mbedtls_pk_sign_ext`

* Used in TLS 1.3 (`ssl_tls13_write_certificate_verify_body`).

#### Uses of `mbedtls_pk_sign_restartable`

* Used in `ssl_write_certificate_verify`.

#### Uses of `mbedtls_pk_verify`

* Used in `mbedtls_pkcs7_data_or_hash_verify`.
* Used in TLS 1.2 servers in `ssl_parse_certificate_verify`.

#### Uses of `mbedtls_pk_verify_restartable`

* Used in `x509_crt_check_signature` under `MBEDTLS_ECP_RESTARTABLE`.
* Used in TLS 1.2 clients in `ssl_parse_server_key_exchange`.

#### Uses of `mbedtls_pk_verify_ext`

* Used in `x509_crt_check_signature`. The possible PSS options come from parsing the child certificate.
* Used in `x509_crt_verifycrl`. The possible PSS options come from parsing the CRL.
* Used in TLS 1.2 (`ssl_parse_server_key_exchange`). The PSS options match the PSA default.
* Used in TLS 1.3 (`ssl_tls13_parse_certificate_verify`). The PSS options match the PSA default.

#### Uses of `mbedtls_pk_write_pubkey`

* Used in certificate writing (`mbedtls_x509write_crt_set_key_identifier`).

#### Uses of `mbedtls_pk_write_pubkey_der`

* Used in certificate writing (`mbedtls_x509write_crt_der`).
* Used in CSR writing (`x509write_csr_der_internal`).

#### Uses of functions in non-fully-PSA builds

* `mbedtls_pk_ec_ro` and `mbedtls_pk_ec_rw` in `ssl_get_ecdh_params_from_cert` for static ECDH when `MBEDTLS_PK_USE_PSA_EC_DATA` or `MBEDTLS_USE_PSA_CRYPTO` is disabled.
* `mbedtls_pk_can_do` in `ssl_pick_cert` for TLS 1.2, only when `MBEDTLS_USE_PSA_CRYPTO` is disabled (otherwise `mbedtls_pk_can_do_ext` is used instead).



## Design study

### Study: context type

Should we keep `mbedtls_pk_context`, or should we have different types for public keys and key pairs?

There are applications such as key stores that need to manipulate both kinds of objects. So we need a public-or-pair type in some way, preferably not as a `void*`.

It's less work to keep the type we have now.

Decision: keep a single type.

### Study: obtaining metadata

The [uses of `mbedtls_pk_get_type`](#uses-of-mbedtls_pk_get_type), [`mbedtls_pk_can_do`](#uses-of-mbedtls_pk_can_do) and [`mbedtls_pk_can_do_ext`](#uses-of-mbedtls_pk_can_do_ext), as well as the [uses of `mbedtls_pk_type_t`](#uses-of-mbedtls_pk_type_t) independently of a PK context, fall into several categories:

* Deciding between RSA and ECC keys. This can be done based on a PSA key type.
* For ECC keys, determining whether the key is earmarked for ECDH (see [“Old PK context constructions”](#old-pk-context-constructions)). This can be done based on a PSA algorithm policy or usage policy.
* Giving different treatment to transparent and opaque PK objects. Outside of `pk*.c`, this only happens in `ssl_get_ecdh_params_from_cert`, which is static ECDH which will be removed in Mbed TLS 4.0.
* Only in X.509 code that tracks PK types, deciding between RSA algorithms (PKCS\#1v1.5 vs PSS). Although the X.509 code uses `MBEDTLS_PK_ECDSA`, it is not treated differently from `MBEDTLS_PK_ECKEY`.

To keep things simple, we will use PSA metadata wherever possible. Each PK object has the same metadata as a PSA key, and these are the metadata of the underlying PSA key if there is one: type, bit-size, algorithm, usage.

```
psa_key_type_t mbedtls_pk_get_psa_type(const mbedtls_pk_context *pk);
size_t mbedtls_pk_get_bitlen(const mbedtls_pk_context *pk); // already exists
psa_algorithm_t mbedtls_pk_get_algorithm(const mbedtls_pk_context *pk);
psa_key_usage_t mbedtls_pk_get_usage(const mbedtls_pk_context *pk);
```

Since the current `mbedtls_pk_type_t` is inconvenient (see [“Old type and policy”](#old-type-and-policy)), we won't try to preserve it as is. We can handle it in two plausible ways:

* Remove `mbedtls_pk_type_t`, `mbedtls_pk_get_type` and `mbedtls_pk_can_do` altogether.
* Keep `mbedtls_pk_type_t` and associated functions, but only keep `MBEDTLS_PK_NONE`, `MBEDTLS_PK_RSA` and `MBEDTLS_PK_ECKEY`. This makes the API less clean, but means less code to rewrite.

### Study: choosing policies when parsing a key

Keys parsed by PK can be used with multiple algorithms which fall under two usage categories for each key type family:

* RSA: signature with `PSA_ALG_RSA_PKCS1V15_SIGN(hash_alg)`, `PSA_ALG_RSA_PSS(hash_alg)` or `PSA_ALG_RSA_PSS_ANY_SALT(hash_alg)`; encryption with `PSA_ALG_RSA_OAEP(hash_alg)` (`PSA_ALG_RSA_PKCS1V15_CRYPT` will no longer be supported).
* ECC: signature with `PSA_ALG_ECDSA(hash_alg)` or `PSA_ALG_DETERMINISTIC_ECDSA(hash_alg)` (and likely soon `PSA_ALG_PURE_EDDSA`, `PSA_ALG_ED25519PH`, `PSA_ALG_ED448PH`); key agreement with `PSA_ALG_ECDH`.

When it comes to PSA policies, The choice of a hash algorithm for a signature algorithm can remain undecided by using `PSA_ALG_ANY_HASH` in the policy. But the usage, and the base algorithm (PKCS1v1.5 vs PSS for RSA signatures, flavor of PSS or ECDSA, as well as hash for OAEP) must be selected at the time a key is imported into PSA.

In Mbed TLS 3.6 (see [“Old PK context constructions”](#old-pk-context-constructions)), parsing a key creates a PK object with limited policy information:

* RSA keys have no policy information.
* EC keys either have no policy information, or are marked as ECDH (due to the presence of the OID `id-ecDH` in the key representation).

In TF-PSA-Crypto 1, we want all keys to be backed by PSA, so they must have a policy. We could create provisional PK objects that do not have a policy set yet, either by storing key material that is not yet imported into PSA, or by extending the PSA API with a “can do everything” policy. We strongly reject extending the PSA API: that would go against its objective of being a modern, principled API. We also reject having provisional PK objects: that would mean a multiplicity of representations and semantics for PK objects which every function that takes a PK object as input would have to deal with.

This gives us two solutions to parse keys and give them policy information. Either we give the parsing function enough policy hints, or we allow changing the policy after the fact.

#### Policy hints for parsing

Before parsing a key, its type is unknown. Therefore policy hints for parsing need to cover all the possible key type. An example of a policy hint would be:

* If the key is RSA, use PSS with the default salt length.
* If the key is ECC-Weierstrass, use randomized ECDSA.
* If the key is EdDSA, use pure EDDSA.

We can either provide these hints as an extra parameter to parsing functions, or by calling a new function on the context before parsing.

This method is flexible, and attractive from a point of view of being clean with policies. But it requires extra APIs, and is weak in terms of cryptographic agility. For example, we can see that adding support for EdDSA means that an application that wants to use EdDSA needs to know about it, or needs to use a predefined policy hint that will make some choice about EdDSA.

For the time being, we will not add a policy hint API. In particular, the parsing functions in TF-PSA-Crypto 1 will not take a policy hint argument. If this approach proves to be desirable, we will add a function to set a policy hint in an unpopulated PK context in TF-PSA-Crypto 1.x.

#### Changing the policy of a PK object

A PSA key's policy cannot be broadened, including by copying: `psa_copy_key` applies the intersection of the current and the new policies. However, there is a loophole: if a key is exportable, then there is no way to prevent exporting it then importing it with an arbitrary policy. The function `mbedtls_pk_import_into_psa` uses this export-import method when its input is a PK opaque key (i.e. a PK object that already has an underlying PSA key).

Bypassing key policies makes PK an unprincipled API. But this is largely in keeping with the current PK API: it only has a very partial understanding of policies and allows them to be bypassed. For example, PK in Mbed TLS 3 allows the same RSA key to be used for both encryption and signature, and for both PKCS\#1 v1.5 and v2 mechanisms.

Thus we propose to officially declare that the PK module does not enforce key policies, and the PK object itself only has informative data about a key's policy. Applications that want control over a key's policy must rely on PSA, for example by making the key non-exportable. This way, PK's semantics regarding policies is not ideal, but at least it's simple.

This approach has the major benefit that we can reuse existing APIs and workflows. An application that uses the Mbed TLS 3.6 workflow of parsing a key and then calling `mbedtls_pk_get_psa_attributes` followed by `mbedtls_pk_import_into_psa` can keep working.

#### Default policy for a parsed key

Having decided that key parsing functions do not receive policy hints (or, in the future, can be called without an explicit policy hint), what policy will they apply?

Parsing a key of an unknown type mostly happens for signature keys. For other usage (encryption, key agreement), PK only supports a single key type, so its parsing flexibility is not needed. Signature keys is what is needed for X.509. Signature keys is what is needed for TLS, given that Mbed TLS 4.0 will not support static-ECDH or RSA-decryption cipher suites. Therefore key parsing will set a default policy that is suitable for signature.

PSA signature policies have an optional hash. PK is not concerned about hash policies at all, so it will use `PSA_ALG_ANY_HASH` in its signature policies. PK will only ever manipulate keys with an explicit hash policy if that was set explicitly by the application.

The remaining question is which signature algorithm when more than one applies.

* RSA: PKCS1v1.5 or PSS, and for PSS public keys, which salt length policy? Both `PSA_ALG_RSA_PKCS1V15_SIGN` and `PSA_ALG_RSA_PSS_ANY_SALT` are sensible here. TODO: decide.
* ECC-Weierstrass: deterministic or randomized ECDSA? In Mbed TLS 3, PK uses deterministic ECDSA when available. TODO: decide, which may be that we don't commit and allow ourselves to change based on currently known risks of side channel attacks.
* ECC-Montgomery: cannot be used for signature.
* ECC-Edwards: we'll decide when we add support for those.

### Study: bridges with PSA

Mbed TLS 3.6 introduced transitional APIs that create a bridge between PSA and PK. With these interfaces, users can create a key through PSA and then use it through PK or vice versa. We can keep these interfaces in the next major version, or evolve them. These interfaces are documented in the [PSA transition guide](https://github.com/Mbed-TLS/mbedtls/blob/mbedtls-3.6.0/docs/psa-transition.md#creating-a-psa-key-via-pk).

Given a PSA key object containing an asymmetric key:

* `mbedtls_pk_setup_opaque` creates a PK context that wraps a PSA key, only for a key pair. This is still a sensible interface in TF-PSA-Crypto 1.0. We may want to extend it to public keys, since all cryptography now goes through PSA, even if there are no concerns about keeping the key material in a separate partition.
* `mbedtls_pk_copy_from_psa` and `mbedtls_pk_copy_public_from_psa` creates a PK context that is a copy of a PSA key, or only the public part of it. This is still a sensible interface in TF-PSA-Crypto 1.0, although we may want to make some workflows more efficient by avoiding a copy.

Given a PK context:

* `mbedtls_pk_import_into_psa`, generally combined with `mbedtls_pk_get_psa_attributes`, creates a PSA key that is a copy of the PK context. This is stil a sensible interface, although the semantics of `mbedtls_pk_get_psa_attributes` will change to some extent: in 3.6 it guesses sensible attributes if the PK context does not have PSA metadata, while in TF-PSA-Crypto all PK contexts have PSA metadata so this function called “get” should return them.
* Mbed TLS 3.6 does not have a public interface to peek at the PSA key ID of a PK context if there is one. We may want to expose this in TF-PSA-Crypto 1.0.

Given that we don't have a strong requirement for a better interface, I propose to go with what we have, and maybe add an interface to peek at the PSA key, with few guarantees (in particular, document that it may fail in future versions for reasons that cannot be anticipated yet).

### Study: object representation

An `mbedtls_pk_context` contains the following information, either explicitly or implicitly:

* Metadata: type, bit-size, policy. This could be local or in the PSA key store.
* Public key. This could be local (in a marshalled format) or in the PSA key store.
* Private key, if the key is a key pair. In TF-PSA-Crypto, this is always a PSA key identifier: we want to get rid of the complexity of supporting local private keys as well.

Keeping a local copy of the metadata is cheap and simple. This data may be out of synch from the PSA metadata in edge cases, but since the metadata of a PSA key does not change, it can only happen if the PSA key is destroyed without going through the PK object, and a new one is created with the same key identifier. So a potential metadata conflict would only increase the chances that the application receives an error rather than use the wrong key. The PK code needs to know the type, bit-size and algorithm (at least for `mbedtls_pk_sign` and `mbedtls_pk_verify` and similar functions). The PK code doesn't need to know the usage policy, but we might keep it for uniformity.

There are several plausible choices for how to store public key objects.

* PSA only: a public key object is stored as a PSA key identifier.
    * Key pairs and public keys thus have the same representation: a PSA key identifier.
* PSA mandatory: a public key object has a PSA key identifier. It may also have a local cache of the public key.
    * Key pairs have the same representation: a PSA key identifier and an optional local cache.
* Export cache: a public key object has a local cache of the public key. It may or may not also refer to a PSA key.
    * Key pairs must have a PSA key identifier, and also have a local cache of the public key.
* Export only: a public key object is stored as its export representation. In terms of resource management, this is the closest to what we have in Mbed TLS 3. In particular, a public key in an X.509 structure only costs heap memory, not a PSA key store entry; this is advantageous when `MBEDTLS_PSA_KEY_STORE_DYNAMIC` is disabled (and it's why we introduced the dynamic key store in Mbed TLS 3.6.1).
    * For key pairs, a local copy of the public key may be optional.
    * For key pairs, a local copy of the public key may be mandatory. This is what the 3.x code does for EC keys when `MBEDTLS_PK_USE_PSA_EC_DATA` is enabled.

There is no security advantage in keeping the public key in a secure enclave, and it can always be exported from PSA. For key pairs, PSA currently does not keep a copy of the public key, and re-creating it can be relatively expensive. For public key objects, keeping both a local copy and a copy in the PSA key store is a waste of memory.

For simplicity of implementation, it's easier if we use the same representation all the time: either PK always wraps around PSA, or public keys are always local. Keeping public keys local preserves the current non-functional behavior of PK regarding resource management, and reduces the amount of work we have to do to evolve from Mbed TLS 3.6 to TF-PSA-Crypto 1.0.

Therefore, in TF-PSA-Crypto 1.0:

* An `mbedtls_pk_context` will keep a copy of the public key in the PSA export format.
* An `mbedtls_pk_context` will reference a PSA key identifier if and only if the context contains a key pair.



## New interfaces

### New implementation of `mbedtls_pk_context`

`mbedtls_pk_context` is a `struct` with the following fields:

* `psa_key_type_t type`

* `psa_key_bits_t bits`

* `psa_key_usage_t usage`

    This is informational. The PK module does not enforce policies.

* `psa_algorithm_t alg`

    This is the base of the algorithm that sign/verify functions use.
    It may be a policy that uses the wildcard `PSA_ALG_ANY_HASH`.
    Sign/verify always use the hash passed to the function, which must match the one in the context if the context doesn't use the wildcard.

* `const uint8_t *public_key`

    Always populated unless the key object is unpopulated.

    Points to `public_key_length` bytes owned by the PK object.
    This is the public key in the PSA export representation.

* `const uint8_t *public_key_length`

* `mbedtls_svc_key_id_t private_key`

    Always populated for a key pair. `MBEDTLS_SVC_KEY_ID_INIT` for a public key.

* `uint32_t flags`

    * `MBEDTLS_PK_FLAG_OWN_PRIVATE_KEY`: if set, destroy `private_key` when destroying the PK context.

A context can be in one of four states:

* Empty: all zero. This is the initial state.
* Prepared: has some metadata set, but no key data. Currently unused.
* Public: all metadata fields are set. `public_key` points to memory owned by the context. `private_key` is zero.
* Pair: all metadata fields are set. `public_key` points to memory owned by the context. `private_key` is a PSA key identifier which may or may not be owned by the context, depending on the presence of `MBEDTLS_PK_FLAG_OWN_PRIVATE_KEY` in `flags`.

### New metadata functions

```
psa_key_type_t mbedtls_pk_get_psa_type(const mbedtls_pk_context *pk);
size_t mbedtls_pk_get_bitlen(const mbedtls_pk_context *pk); // already exists
psa_algorithm_t mbedtls_pk_get_algorithm(const mbedtls_pk_context *pk);
psa_key_usage_t mbedtls_pk_get_usage(const mbedtls_pk_context *pk);
```

These functions just return the information in the context.

Design discussion: [“Study: obtaining metadata”](#study-obtaining-metadata).

### Peeking at the PSA key

```
mbedtls_svc_key_id_t mbedtls_pk_peek_psa_key(const mbedtls_pk_context *pk)
```

Design discussion: [“Study: bridges with PSA”](#study-bridges-with-psa).

### Changing the key policy

TODO: do we need a function to change the policy of an existing context, intended for use after parsing?



## Implementation changes

### Changes to `mbedtls_pk_free`

* Free the public key.
* Free the private key if the `MBEDTLS_PK_FLAG_OWN_PRIVATE_KEY` flag is set.

See: [“Study: obtaining metadata”](#study-obtaining-metadata), [“New implementation of `mbedtls_pk_context`”](#new-implementation-of-mbedtls_pk_context).

### Changes to `mbedtls_pk_can_do_ext`

Adapt the code to use the PSA metadata in the context.

TODO: should randomized and deterministic ECDSA be treated as equivalent?

See: [“Study: obtaining metadata”](#study-obtaining-metadata), [“New implementation of `mbedtls_pk_context`”](#new-implementation-of-mbedtls_pk_context).

### Changes to `mbedtls_pk_get_psa_attributes`

Based on the name of the function, we would expect it to return the attributes in the context. This is unfortunate, because the goal of the function is to construct sensible attributes for a given use case. The function does however take a second input parameter `usage`, so this parameter can sensibly modify the attributes compared to what is in the PK object.

Compared with Mbed TLS 3.6, we expect that the typical workflow produces a key `pk2` with substantially the same attributes:

1. Parse a key into a context `pk1`.
2. Call `mbedtls_pk_get_psa_attributes(pk1, usage_flag, &attributes)`
3. Call `mbedtls_pk_import_into_psa(pk2, &attributes, &key_id)`

TODO: deprecate the name `mbedtls_pk_get_psa_attributes`?

### Changes to `mbedtls_pk_import_into_psa`, `mbedtls_pk_copy_from_psa`, `mbedtls_pk_copy_public_from_psa`

Only implementation changes: use the same logic as when `MBEDTLS_PK_USE_PSA_EC_DATA` is enabled, but now also handling RSA keys.

### Changes to `mbedtls_pk_sign`, `mbedtls_pk_verify`

Apply the signature algorithm in the PK context, with the hash specified as an argument.

If the context specifies a hash, it must match the one passed as an argument. PSA takes care of this for a key pair, but PK must handle this check for a public key.

### Changes to `mbedtls_pk_sign_restartable`, `mbedtls_pk_verify_restartable`

See [“Changes to `mbedtls_pk_sign`, `mbedtls_pk_verify`”](#changes-to-mbedtls_pk_sign-mbedtls_pk_verify).

In addition, use the new PSA API for interruptible sign/verify. If that API is not present or fails, fall back to the non-restartable function.

### Changes to `mbedtls_pk_check_pair`

Always apply the same strategy:

1. Check that `prv->type == PSA_KEY_TYPE_KEY_PAIR_OF_PUBLIC_KEY(pub->type)`.
2. Check that `prv->bits == pub->bits`.
3. Check that `prv->public_key_length` == `pub->public_key_length`.
3. Check that `prv->public_key` and `pub->public_key` have the same content.

### Changes to key parsing functions

These functions now apply a default policy to keys, which is the same as what Mbed TLS 3.6 does in `mbedtls_pk_get_psa_attributes` for the usage `SIGN_HASH` for a key pair, `VERIFY_HASH` for a public key.

Use the same logic as when `MBEDTLS_PK_USE_PSA_EC_DATA` is enabled, but now also handling RSA keys.

### Changes to key writing functions

Only implementation changes: use the same logic as when `MBEDTLS_PK_USE_PSA_EC_DATA` is enabled, but now also handling RSA keys.



## Implementation tasks

### Task: debug removal

Dependencies: none.

* In `debug.c`, rewrite `debug_print_pk` and its auxiliary functions to print the PSA export format of the public key in hex instead of what we have now.
* Adapt the expected output in the relevant test cases in `test_suite_debug.data`.
* Remove `mbedtls_pk_debug_type`, `mbedtls_pk_debug_item`, `MBEDTLS_PK_DEBUG_MAX_ITEMS`, `mbedtls_pk_debug` and their tests.

### Task: test X.509 ID flags

Dependencies: none.

The macro `MBEDTLS_X509_ID_FLAG` constructs a flag from a value in the range 1–31. (This could be extended to 1–32 if we changed `1 <<` to `1u <<`.) In Mbed TLS 3, it is used on valid values of type `mbedtls_pk_type_t`, `mbedtls_md_type_t` and `mbedtls_ecp_group_id`. When we change the encoding of these types or their successors, we need to either preserve the property that all the values are less than 32, or change the way X.509 flags work.

The goal of this task is to add unit tests in the respective modules, documented as being for the benefit of `MBEDTLS_X509_ID_FLAG`. Also, add a comment in `x509_crt.h` warning that if we change the set of types that `MBEDTLS_X509_ID_FLAG` is applied to, we must pay attention to the value limitation and update those tests.

### Task: remove obsolete sample programs

Dependencies: none.

* Remove sample programs for low-level interfaces: `pkey/dh_*`, `pkey/ec*`, `pkey/mpi_*`, `pkey/rsa_*`.
* Remove sample programs that rely on low-level interfaces, although they are still meaningful: `programs/key_app`, `programs/key_app_writer`. Ideally those should be adapted, but they would be almost complete rewrites since access to low-level representations is no longer possible.
* Remove `pkey/pk_encrypt` and `pkey/pk_decrypt`. Ideally those should be adapted, but they would be almost complete rewrites since the PK module no longer does encryption.

### Task: sample program demos

Dependencies: none.

Goal: have smoke tests for the sample programs that we're migrating.

* Take `cert_write_demo.sh` from https://github.com/Mbed-TLS/mbedtls/pull/2698 and make it work on `development`. This should preferably be backported to 3.6. This script covers `pkey/gen_key`, `x509/cert_req`, `x509/cert_write`, `x509/cert_app` and `x509/req_app`.
* Write an auxiliary script parametrized by a key type for the sequence of `pkey/gen_key`, `pkey/pk_sign` and `pkey/pk_verify`. Also demonstrate that the signature verification fails if the message has changed. Use it to make a `sign_rsa_demo.sh` and a `sign_ecdsa_demo.sh`.



## Open questions
