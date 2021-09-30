This document lists current limitations of the PSA Crypto API (as of version
1.1) that may impact our ability to (1) use it for all crypto operations in
TLS and X.509 and (2) support isolation of all long-term secrets in TLS (that
is, goals G1 and G2 in [strategy.md][] in the same directory).

This is supposed to be a complete list, based on a exhaustive review of crypto
operations done in TLS and X.509 code, but of course it's still possible that
subtle-but-important issues have been missed. The only way to be really sure
is, of course, to actually do the migration work.

Limitations relevant for G1 (performing crypto operations)
==========================================================

Restartable ECC operations
--------------------------

There is currently no support for that in PSA at all. API design, as well as
implementation, would be non-trivial.

Currently, `MBEDTLS_USE_PSA_CRYPTO` is simply incompatible with
`MBEDTLS_ECP_RESTARTABLE`.

Arbitrary parameters for FFDH
-----------------------------

Currently, the PSA Crypto API can only perform FFDH with a limited set of
well-know parameters (some of them defined in the spec, but implementations
are free to extend that set).

TLS 1.2 (and earlier) on the other hand have the server send explicit
parameters (P and G) in is ServerKeyExchange message. This has been found to
be suboptimal for security, as it is prohibitively hard for the client to
verify the strength of these parameters. This led to the development of RFC
7919 which allows use of named groups in TLS 1.2 - however as this is only an
extension, servers can still send custom parameters if they don't support the
extension.

In TLS 1.3 the situation will be simpler: named groups are the only
option, so the current PSA Crypto API is a good match for that. (Not
coincidentally, the groups used by RFC 7919 and TLS 1.3 are part those defined
in the specification.)

There are several options here:

1. Implement support for custom FFDH parameters in PSA Crypto: this would pose
   non-trivial API design problem, but most importantly seems backwards, as
the crypto community is moving away from custom FFDH parameters.
2. Drop the DHE-RSA and DHE-PSK key exchanges in TLS 1.2 when moving to PSA.
3. Implement RFC 7919, support DHE-RSA and DHE-PSK only in conjunction with it
   when moving to PSA. We can modify our server so that it only selects a DHE
   ciphersuite if the client offered name FFDH groups; unfortunately
client-side the only option is to offer named groups and break the handshake
if the server didn't take on our offer. This is not fully satisfying, but is
perhaps the least unsatisfying option in terms of result; it's also probably
the one that requires the most work, but it would deliver value beyond PSA
migration by implementing RFC 7919.

RSA-PSS parameters
------------------

RSA-PSS signatures are defined by PKCS#1 v2, re-published as RFC 8017
(previously RFC 3447).

As standardized, the signature scheme takes several parameters, in addition to
the hash algorithm potentially used to hash the message being signed:
- a hash algorithm use for the encoding function
- a mask generation function
  - most commonly MGF1, which in turn is parametrized by a hash algorithm
- a salt length

Both the existing `mbedtls_` API and the PSA API support only MGF1 as the
generation function, but there are discrepancy in handling the salt length and
which of the various hash algorithms can differ from each other.

### API comparison

- RSA:
  - signature: `mbedtls_rsa_rsassa_pss_sign()`
    - message hashed externally
    - encoding hash = MGF1 hash (from context, or argument = message hash)
    - salt length: always using the maximum legal value
  - signature: `mbedtls_rsa_rsassa_pss_sign_ext()`
    - message hashed externally
    - encoding hash = MGF1 hash (from context, or argument = message hash)
    - salt length: specified explicitly
  - verification: `mbedtls_rsassa_pss_verify()`
    - message hashed externally
    - encoding hash = MGF1 hash (from context, or argument = message hash)
    - salt length: any valid length accepted
  - verification: `mbedtls_rsassa_pss_verify_ext()`
    - message hashed externally
    - encoding hash = MGF1 hash from dedicated argument
    - expected salt length: specified explicitly, can specify "ANY"
- PK:
  - signature: not supported
  - verification: `mbedtls_pk_verify_ext()`
    - message hashed externally
    - encoding hash = MGF1 hash, specified explicitly
    - expected salt length: specified explicitly, can specify "ANY"
- PSA:
  - algorithm specification:
    - hash alg used for message hashing, encoding and MGF1
    - salt length cannot be specified
  - signature generation:
    - salt length: always using the maximum legal value
  - verification:
    - salt length: any valid length accepted

The RSA/PK API is in principle more flexible than the PSA Crypto API. The
following sub-sections study whether and how this matters in practice.

### Use in X.509

RFC 4055 Section 3.1 defines the encoding of RSA-PSS that's used in X.509.
It allows independently specifying the message hash (also used for encoding
hash), the MGF (and its hash if MGF1 is used), and the salt length (plus an
extra parameter "trailer field" that doesn't vary in practice"). These can be
encoded as part of the key, and of the signature. If both encoding are
presents, all values must match except possibly for the salt length, where the
value from the signature parameters is used.

In Mbed TLS, RSA-PSS parameters can be parsed and displayed for various
objects (certificates, CRLs, CSRs). During parsing, the following properties
are enforced:
- (the extra "trailer field" parameter must has its default value)
- the mask generation function is MGF1
- encoding hash = message hashing algorithm (may differ from MGF1 hash)

When it comes to cryptographic operations, only two things are supported:
- verifying the signature on a certificate from its parent;
- verifying the signature on a CRL from the issuing CA.

The verification is done using `mbedtls_pk_verify_ext()`.

Note: since X.509 parsing ensures that message hash = encoding hash, and
`mbedtls_pk_verify_ext()` use encoding hash = mgf1 hash, it looks like all
three hash algorithms must be equal, which would be good news as it would
match a limitation of the PSA API. (TODO: double-check that.)

Also, since we only use signature verification, the fact that PSA accepts any
valid salt length means that no valid certificate would be wrongly rejected;
however it means that signatures that don't match the announced salt length
would be incorrectly accepted. At first glance, it looks like this doesn't
allow an attacker to forge certificates, so this might be acceptable in
practice, while not fully implementing all the checks in the standard. (TODO:
triple-check that.)

It is unclear what parameters people use in practice.

### Use in TLS

In TLS 1.2 (or lower), RSA-PSS signatures are never used, except via X.509.

In TLS 1.3, RSA-PSS signatures can be used directly in the protocol (in
addition to indirect use via X.509). It has two sets of three signature
algorithm identifiers (for SHA-256, SHA-384 and SHA-512), depending of what
the OID of the public key is (rsaEncryption or RSASSA-PSS).

In both cases, it specifies that:
- the mask generation function is MGF1
- all three hashes are equal
- the length of the salt MUST be equal to the length of the digest algorithm

When signing, the salt length picked by PSA is the one required by TLS 1.3
(unless the key is unreasonably small).

When verifying signatures, again is doesn't look like accepting any salt
length would give an attacker any advantage, but this must be triple-checked
(TODO).

### Current testing - X509

TODO: look at the parameters used by the various test files

- server9.crt
    -HASH
    -badsign
    -defaults
    -bad-saltlen
    -bad-mgfhash
- crl-rsa-pss-HASH.pem
- server9.req.HASH

### Possible course of actions

TODO - once the previous section has been completed

Limitations relevant for G2 (isolation of long-term secrets)
============================================================

Custom key derivations for mixed-PSK handshake
----------------------------------------------

Currently, `MBEDTLS_USE_PSA_CRYPTO` enables the new configuration function
`mbedtls_ssl_conf_psk_opaque()` which allows a PSA-held key to be used for the
(pure) `PSK` key exchange in TLS 1.2. This requires that the derivation of the
Master Secret (MS) be done on the PSA side. To support this, an algorithm
family `PSA_ALG_TLS12_PSK_TO_MS(hash_alg)` was added to PSA Crypto.

If we want to support key isolation for the "mixed PSK" key exchanges:
DHE-PSK, RSA-PSK, ECDHE-PSK, where the PSK is concatenated with the result of
a DH key agreement (resp. RSA decryption) to form the pre-master secret (PMS)
from which the MS is derived. If the value of the PSK is to remain hidden, we
need the derivation PSK + secondary secret -> MS to be implemented as an
ad-hoc PSA key derivation algorithm.

Adding this new, TLS-specific, key derivation algorithm to PSA Crypto should
be no harder than it was to add `PSA_ALG_TLS12_PSK_TO_MS()` but still requires
an extension to PSA Crypto.

Note: looking at RFCs 4279 and 5489, it appears that the structure of the PMS
is always the same: 2-byte length of the secondary secret, secondary secret,
2-byte length of the PSK, PSK. So, a single key derivation algorithm should be
able to cover the 3 key exchanges DHE-PSK, RSA-PSK and ECDHE-PSK. (That's a
minor gain: adding 3 algorithms would not be a blocker anyway.)

Note: if later we want to also isolate short-term secret (G3), the "secondary
secret" (output of DHE/ECDHE key agreement or RSA decryption) could be a
candidate. This wouldn't be a problem as the PSA key derivation API always
allows inputs from key slots. (Tangent: the hard part in isolating the result
of RSA decryption would be still checking that is has the correct format:
48 bytes, the first two matching the TLS version - note that this is timing
sensitive.)

