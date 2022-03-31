This document lists current limitations of the PSA Crypto API (as of version
1.1) that may impact our ability to (1) use it for all crypto operations in
TLS and X.509 and (2) support isolation of all long-term secrets in TLS (that
is, goals G1 and G2 in [strategy.md](strategy.md) in the same directory).

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

Things that are in the API but not implemented yet
--------------------------------------------------

PSA Crypto has an API for FFDH, but it's not implemented in Mbed TLS yet.
(Regarding FFDH, see the next section as well.) See issue [3261][ffdh] on
github.

[ffdh]: https://github.com/Mbed-TLS/mbedtls/issues/3261

PSA Crypto has an experimental API for EC J-PAKE, but it's not implemented in
Mbed TLS yet. See the [EC J-PAKE follow-up EPIC][ecjp] on github.

[ecjp]: https://github.com/orgs/Mbed-TLS/projects/1#column-17950140

Arbitrary parameters for FFDH
-----------------------------

(See also the first paragraph in the previous section.)

Currently, the PSA Crypto API can only perform FFDH with a limited set of
well-known parameters (some of them defined in the spec, but implementations
are free to extend that set).

TLS 1.2 (and earlier) on the other hand have the server send explicit
parameters (P and G) in its ServerKeyExchange message. This has been found to
be suboptimal for security, as it is prohibitively hard for the client to
verify the strength of these parameters. This led to the development of RFC
7919 which allows use of named groups in TLS 1.2 - however as this is only an
extension, servers can still send custom parameters if they don't support the
extension.

In TLS 1.3 the situation will be simpler: named groups are the only
option, so the current PSA Crypto API is a good match for that. (Not
coincidentally, all the groups used by RFC 7919 and TLS 1.3 are included
in the PSA specification.)

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
- a hash algorithm used for the encoding function
- a mask generation function
  - most commonly MGF1, which in turn is parametrized by a hash algorithm
- a salt length
- a trailer field - the value is fixed to 0xBC by PKCS#1 v2.1, but was left
  configurable in the original scheme; 0xBC is used everywhere in pratice.

Both the existing `mbedtls_` API and the PSA API support only MGF1 as the
generation function (and only 0xBC as the trailer field), but there are
discrepancies in handling the salt length and which of the various hash
algorithms can differ from each other.

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
    - salt length can be either "standard" (<= hashlen, see note) or "any"
  - signature generation:
    - salt length: always <= hashlen (see note) and random salt
  - verification:
    - salt length: either <= hashlen (see note), or any depending on algorithm

Note: above, "<= hashlen" means that hashlen is used if possible, but if it
doesn't fit because the key is too short, then the maximum length that fits is
used.

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
- the extra "trailer field" parameter must have its default value
- the mask generation function is MGF1
- encoding hash = message hashing algorithm (may differ from MGF1 hash)

When it comes to cryptographic operations, only two things are supported:
- verifying the signature on a certificate from its parent;
- verifying the signature on a CRL from the issuing CA.

The verification is done using `mbedtls_pk_verify_ext()`.

Note: since X.509 parsing ensures that message hash = encoding hash, and
`mbedtls_pk_verify_ext()` uses encoding hash = mgf1 hash, it looks like all
three hash algorithms must be equal, which would be good news as it would
match a limitation of the PSA API.

It is unclear what parameters people use in practice. It looks like by default
OpenSSL picks saltlen = keylen - hashlen - 2 (tested with openssl 1.1.1f).
The `certool` command provided by GnuTLS seems to be picking saltlen = hashlen
by default (tested with GnuTLS 3.6.13). FIPS 186-4 requires 0 <= saltlen <=
hashlen.

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

When verifying signatures, PSA will by default enforce the salt len is the one
required by TLS 1.3.

### Current testing - X509

All test files use the default trailer field of 0xBC, as enforced by our
parser. (There's a negative test for that using the
`x509_parse_rsassa_pss_params` test function and hex data.)

Files with "bad" in the name are expected to be invalid and rejected in tests.

**Test certificates:**

server9-bad-mgfhash.crt (announcing mgf1(sha224), signed with another mgf)
         Hash Algorithm: sha256
         Mask Algorithm: mgf1 with sha224
          Salt Length: 0xDE
server9-bad-saltlen.crt (announcing saltlen = 0xDE, signed with another len)
         Hash Algorithm: sha256
         Mask Algorithm: mgf1 with sha256
          Salt Length: 0xDE
server9-badsign.crt (one bit flipped in the signature)
         Hash Algorithm: sha1 (default)
         Mask Algorithm: mgf1 with sha1 (default)
          Salt Length: 0xEA
server9-defaults.crt
         Hash Algorithm: sha1 (default)
         Mask Algorithm: mgf1 with sha1 (default)
          Salt Length: 0x14 (default)
server9-sha224.crt
         Hash Algorithm: sha224
         Mask Algorithm: mgf1 with sha224
          Salt Length: 0xE2
server9-sha256.crt
         Hash Algorithm: sha256
         Mask Algorithm: mgf1 with sha256
          Salt Length: 0xDE
server9-sha384.crt
         Hash Algorithm: sha384
         Mask Algorithm: mgf1 with sha384
          Salt Length: 0xCE
server9-sha512.crt
         Hash Algorithm: sha512
         Mask Algorithm: mgf1 with sha512
          Salt Length: 0xBE
server9-with-ca.crt
         Hash Algorithm: sha1 (default)
         Mask Algorithm: mgf1 with sha1 (default)
          Salt Length: 0xEA
server9.crt
         Hash Algorithm: sha1 (default)
         Mask Algorithm: mgf1 with sha1 (default)
          Salt Length: 0xEA

These certificates are signed with a 2048-bit key. It appears that they are
all using saltlen = keylen - hashlen - 2, except for server9-defaults which is
using saltlen = hashlen.

**Test CRLs:**

crl-rsa-pss-sha1-badsign.pem
         Hash Algorithm: sha1 (default)
         Mask Algorithm: mgf1 with sha1 (default)
          Salt Length: 0xEA
crl-rsa-pss-sha1.pem
         Hash Algorithm: sha1 (default)
         Mask Algorithm: mgf1 with sha1 (default)
          Salt Length: 0xEA
crl-rsa-pss-sha224.pem
         Hash Algorithm: sha224
         Mask Algorithm: mgf1 with sha224
          Salt Length: 0xE2
crl-rsa-pss-sha256.pem
         Hash Algorithm: sha256
         Mask Algorithm: mgf1 with sha256
          Salt Length: 0xDE
crl-rsa-pss-sha384.pem
         Hash Algorithm: sha384
         Mask Algorithm: mgf1 with sha384
          Salt Length: 0xCE
crl-rsa-pss-sha512.pem
         Hash Algorithm: sha512
         Mask Algorithm: mgf1 with sha512
          Salt Length: 0xBE

These CRLs are signed with a 2048-bit key. It appears that they are
all using saltlen = keylen - hashlen - 2.

**Test CSRs:**

server9.req.sha1
         Hash Algorithm: sha1 (default)
         Mask Algorithm: mgf1 with sha1 (default)
          Salt Length: 0x6A
server9.req.sha224
         Hash Algorithm: sha224
         Mask Algorithm: mgf1 with sha224
          Salt Length: 0x62
server9.req.sha256
         Hash Algorithm: sha256
         Mask Algorithm: mgf1 with sha256
          Salt Length: 0x5E
server9.req.sha384
         Hash Algorithm: sha384
         Mask Algorithm: mgf1 with sha384
          Salt Length: 0x4E
server9.req.sha512
         Hash Algorithm: sha512
         Mask Algorithm: mgf1 with sha512
          Salt Length: 0x3E

These CSRss are signed with a 2048-bit key. It appears that they are
all using saltlen = keylen - hashlen - 2.

### Possible courses of action

There's no question about what to do with TLS (any version); the only question
is about X.509 signature verification. Options include:

1. Doing all verifications with `PSA_ALG_RSA_PSS_ANY_SALT` - while this
   wouldn't cause a concrete security issue, this would be non-compliant.
2. Doing verifications with `PSA_ALG_RSA_PSS` when we're lucky and the encoded
   saltlen happens to match hashlen, and falling back to `ANY_SALT` otherwise.
Same issue as with the previous point, except more contained.
3. Reject all certificates with saltlen != hashlen. This includes all
   certificates generate with OpenSSL using the default parameters, so it's
probably not acceptable.
4. Request an extension to the PSA Crypto API and use one of the above options
   in the meantime. Such an extension seems inconvenient and not motivated by
strong security arguments, so it's unclear whether it would be accepted.

HKDF: Expand not exposed on its own (TLS 1.3)
---------------------------------------------

The HKDF function uses and Extract-then-Expand approch, that is:

        HKDF(x, ...) = HKDF-Expand(HKDF-Extract(x, ...), ...)

Only the full HKDF function is safe in general, however there are cases when
one case safely use the individual Extract and Expand; the TLS 1.3 key
schedule does so. Specifically, looking at the [hierarchy of secrets][13hs]
is seems that Expand and Extract are always chained, so that this hierarchy
can be implemented using only the full HKDF. However, looking at the
derivation of traffic keys (7.3) and the update mechanism (7.2) it appears
that calls to HKDF-Expand are iterated without any intermediated call to
HKDF-Extract : that is, the traffic keys are computed as

        HKDF-Expand(HKDF-Expand(HKDF-Extract(...)))

(with possibly more than two Expands in a row with update).

[13hs]: https://datatracker.ietf.org/doc/html/rfc8446#page-93

In the short term (early 2022), we'll work around that by re-implementing HKDF
in `ssl_tls13_keys.c` based on the `psa_mac_` APIs (for HMAC).

In the long term, it is desirable to extend the PSA API. See
https://github.com/ARM-software/psa-crypto-api/issues/539

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

HKDF: Expand not exposed on its own (TLS 1.3)
---------------------------------------------

See the section with the same name in the G1 part above for background.

The work-around mentioned there works well enough just for acceleration, but
is not sufficient for key isolation or generally proper key management (it
requires marking keys are usable for HMAC while they should only be used for
key derivation).

The obvious long-term solution is to make HKDF-Expand available as a new KDF
(in addition to the full HKDF) in PSA (with appropriate warnings in the
documentation).
