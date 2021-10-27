This document explains the strategy that was used so far in starting the
migration to PSA Crypto and mentions future perspectives and open questions.

Goals
=====

Several benefits are expected from migrating to PSA Crypto:

G1. Use PSA Crypto drivers when available.
G2. Allow isolation of long-term secrets (for example, private keys).
G3. Allow isolation of short-term secrets (for example, TLS sesssion keys).
G4. Have a clean, unified API for Crypto (retire the legacy API).
G5. Code size: compile out our implementation when a driver is available.

Currently, some parts of (G1) and (G2) are implemented when
`MBEDTLS_USE_PSA_CRYPTO` is enabled. For (G2) to take effect, the application
needs to be changed to use new APIs.

Generally speaking, the numbering above doesn't mean that each goal requires
the preceding ones to be completed, for example G2-G5 could be done in any
order; however they all either depend on G1 or are just much more convenient
if G1 is done before (note that this is not a dependency on G1 being complete,
it's more like each bit of G2-G5 is helped by some speficic bit in G1).

So, a solid intermediate goal would be to complete (G1) when
`MBEDTLS_USA_PSA_CRYPTO` is enabled - that is, all crypto operations in X.509
and TLS would be done via the PSA Crypto API.

Compile-time options
====================

We currently have two compile-time options that are relevant to the migration:

- `MBEDTLS_PSA_CRYPTO_C` - enabled by default, controls the presence of the PSA
  Crypto APIs.
- `MBEDTLS_USE_PSA_CRYPTO` - disabled by default (enabled in "full" config),
  controls usage of PSA Crypto APIs to perform operations in X.509 and TLS
(G1 above), as well as the availability of some new APIs (G2 above).

The reasons why `MBEDTLS_USE_PSA_CRYPTO` is optional and disabled by default
are:
- it's incompatible with `MBEDTLS_ECP_RESTARTABLE`, `MBEDTLS_PSA_CRYPTO_CONFIG` and `MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER`;
- to avoid a hard/default dependency of X509 and TLS and
  `MBEDTLS_PSA_CRYPTO_C`, mostly reasons of code size, and historically
concerns about the maturity of the PSA code (which we might want to
re-evaluate).

The downside of this approach is that until we feel ready to make
`MBDEDTLS_USE_PSA_CRYPTO` non-optional (always enabled), we have to maintain
two versions of some parts of the code: one using PSA, the other using the
legacy APIs. However, see next section for strategies that can lower that
cost. The rest of this section explains the reasons for the
incompatibilities mentioned above.

### `MBEDTLS_ECP_RESTARTABLE`

Currently this option controls not only the presence of restartable APIs in
the crypto library, but also their use in the TLS and X.509 layers. Since PSA
Crypto does not support restartable operations, there's a clear conflict: the
TLS and X.509 layers can't both use only PSA APIs and get restartable
behaviour.

Supporting this in PSA is on our roadmap (it's been requested). But it's way
below generalizing support for `MBEDTLS_USE_PSA_CRYPTO` for “mainstream” use
cases on our priority list. So in the medium term `MBEDTLS_ECP_RESTARTABLE` is
incompatible with `MBEDTLS_USE_PSA_CRYPTO`.

Note: it is possible to make the options compatible at build time simply by
deciding that when `USE_PSA_CRYPTO` is enabled, then `MBEDTLS_ECP_RESTARTABLE`
cease to have any effect on X.509 and TLS: it simply controls the presence of
the APIs in libmbedcrypto. (Or we could split `ECP_RESTARTABLE` into several
options to achieve a similar effect.) This would allow people to use
restartable ECC in non-TLS, non-X509 code (for example firmware verification)
with a build that also uses PSA for TLS and X509), if there is an interest for
that.

### `MBEDTLS_PSA_CRYPTO_CONFIG`

X509 and TLS code use `MBEDTLS_xxx` macros to decide whether an algorithm is
supported. This doesn't make `MBEDTLS_USE_PSA_CRYPTO` incompatible with
`MBEDTLS_PSA_CRYPTO_CONFIG` per se, but it makes it incompatible with most
useful uses of `MBEDTLS_PSA_CRYPTO_CONFIG`. The point of
`MBEDTLS_PSA_CRYPTO_CONFIG` is to be able to build a library with support for
an algorithm through a PSA driver only, without building the software
implementation of that algorithm. But then the TLS code would consider the
algorithm unavailable.

This is tracked in https://github.com/ARMmbed/mbedtls/issues/3674 and
https://github.com/ARMmbed/mbedtls/issues/3677. But now that I look at it with
fresh eyes, I don't think the approach we were planning to use would actually
works. This needs more design effort.

This is something we need to support eventually, and several partners want it.
I don't know what the priority is for `MBEDTLS_USE_PSA_CRYPTO` between
improving driver support and covering more of the protocol. It seems to me
that it'll be less work overall to first implement a good architecture for
`MBEDTLS_USE_PSA_CRYPTO + MBEDTLS_PSA_CRYPTO_CONFIG` and then extend to more
protocol featues, because implementing that architecture will require changes
to the existing code and the less code there is at this point the better,
whereas extending to more procotol features will require the same amount of
work either way.

### `MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER`

When `MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER` is enabled, the library is
built for use with an RPC server that dispatches PSA crypto function calls
from multiple clients. In such a build, all the `psa_xxx` functions that take
would normally take a `psa_key_id_t` as argument instead take a structure
containing both the key id and the client id. And so if e.g. a TLS function
calls `psa_import_key`, it would have to pass this structure, not just the
`psa_key_id_t` key id.

A solution is to use `mbedtls_svc_key_id_t` throughout instead of
`psa_key_id_t`, and use similar abstractions to define values. That's what we
do in unit tests of PSA crypto itself to support both cases. That abstraction
is more confusing to readers, so the less we use it the better.

I don't think supporting TLS and an RPC interface in the same build is an
important use case (I don't remember anyone requesting it). So I propose to
ignore it in the design: we just don't intend to support it.

Taking advantage of the existing abstractions layers - or not
=============================================================

The Crypto library in Mbed TLS currently has 3 abstraction layers that offer
algorithm-agnostic APIs for a class of algorithms:

- MD for messages digests aka hashes (including HMAC)
- Cipher for symmetric ciphers (included AEAD)
- PK for asymmetric (aka public-key) cryptography (excluding key exchange)

Note: key exchange (FFDH, ECDH) is not covered by an abstraction layer.

These abstraction layers typically provide, in addition to the API for crypto
operations, types and numerical identifiers for algorithms (for
example `mbedtls_cipher_mode_t` and its values). The
current strategy is to keep using those identifiers in most of the code, in
particular in existing structures and public APIs, even when
`MBEDTLS_USE_PSA_CRYPTO` is enabled. (This is not an issue for G1, G2, G3
above, and is only potentially relevant for G4.)

The are multiple strategies that can be used regarding the place of those
layers in the migration to PSA.

Silently call to PSA from the abstraction layer
-----------------------------------------------

- Provide a new definition (conditionally on `USE_PSA_CRYPTO`) of wrapper
  functions in the abstraction layer, that calls PSA instead of the legacy
crypto API.
- Upside: changes contained to a single place, no need to change TLS or X.509
  code anywhere.
- Downside: tricky to implement if the PSA implementation is currently done on
  top of that layer (dependency loop).

This strategy is currently used for ECDSA signature verification in the PK
layer, and could be extended to all operations in the PK layer.

This strategy is not very well suited to the Cipher and MD layers, as the PSA
implementation is currently done on top of those layers.

Replace calls for each operation
--------------------------------

- For every operation that's done through this layer in TLS or X.509, just
  replace function call with calls to PSA (conditionally on `USE_PSA_CRYPTO`)
- Upside: conceptually simple, and if the PSA implementation is currently done
  on top of that layer, avoids concerns about dependency loops.
- Downside: TLS/X.509 code has to be done for each operation.

This strategy is currently used for the MD layer. (Currently only a subset of
calling places, but could be extended to all of them.)

Opt-in use of PSA from the abstraction layer
--------------------------------------------

- Provide a new way to set up a context that causes operations on that context
  to be done via PSA.
- Upside: changes mostly contained in one place, TLS/X.509 code only needs to
  be changed when setting up the context, but not when using it. In
  particular, no changes to/duplication of existing public APIs that expect a
  key to be passed as a context of this layer (eg, `mbedtls_pk_context`).
- Upside: avoids dependency loop when PSA implemented on top of that layer.
- Downside: when the context is typically set up by the application, requires
  changes in application code.

There are two variants of this strategy: one where using the new setup
function also allows for key isolation (the key is only held by PSA,
supporting both G1 and G2 in that area), and one without isolation (the key is
still stored outsde of PSA most of the time, supporting only G1).

This strategy, with support for key isolation, is currently used for ECDSA
signature generation in the PK layer - see `mbedtls_pk_setup_opaque()`. This
allows use of PSA-held private ECDSA keys in TLS and X.509 with no change to
the TLS/X.509 code, but a contained change in the application. If could be
extended to other private key operations in the PK layer.

This strategy, without key isolation, is also currently used in the Cipher
layer - see `mbedtls_cipher_setup_psa()`. This allows use of PSA for cipher
operations in TLS with no change to the application code, and a
contained change in TLS code. (It currently only supports a subset of ciphers,
but could easily be extended to all of them.)

Note: for private key operations in the PK layer, both the "silent" and the
"opt-in" strategy can apply, and can complement each other, as one provides
support for key isolation, but at the (unavoidable) code of change in
application code, while the other requires no application change to get
support for drivers, but fails to provide isolation support.

Migrating away from the legacy API
==================================

This section briefly introduces questions and possible plans towards G4,
mainly as they relate to choices in previous stages.

The role of the PK/Cipher/MD APIs in user migration
---------------------------------------------------

We're currently taking advantage of the existing PK and Cipher layers in order
to reduce the number of places where library code needs to be changed. It's
only natural to consider using the same strategy (with the PK, MD and Cipher
layers) for facilitating migration of application code.

Note: a necessary first step for that would be to make sure PSA is no longer
implemented of top of the concerned layers

### Zero-cost compatibility layer?

The most favourable case is if we can have a zero-cost abstraction (no
runtime, RAM usage or code size penalty), for example just a bunch of
`#define`s, essentialy mapping `mbedtls_` APIs to their `psa_` equivalent.

Unfortunately that's unlikely fully work. For example, the MD layer uses the
same context type for hashes and HMACs, while the PSA API (rightfully) has
distinct operation types. Similarly, the Cipher layer uses the same context
type for unauthenticated and AEAD ciphers, which again the PSA API
distinguishes.

It is unclear how much value, if any, a zero-cost compatibility layer that's
incomplete (for example, for MD covering only hashes, or for Cipher covering
only AEAD) or differs significantly from the existing API (for example,
introducing new context types) would provide to users.

### Low-cost compatibility layers?

Another possibility is to keep most or all of the existing API for the PK, MD
and Cipher layers, implemented on top of PSA, aiming for the lowest possible
cost. For example, `mbedtls_md_context_t` would be defined as a (tagged) union
of `psa_hash_operation_t` and `psa_mac_operation_t`, then `mbedtls_md_setup()`
would initialize the correct part, and the rest of the functions be simple
wrappers around PSA functions. This would vastly reduce the complexity of the
layers compared to the existing (no need to dispatch through function
pointers, just call the corresponding PSA API).

Since this would still represent a non-zero cost, not only in terms of code
size, but also in terms of maintainance (testing, etc.) this would probably
be a temporary solution: for example keep the compatibility layers in 4.0 (and
make them optional), but remove them in 5.0.

Again, this provides the most value to users if we can manage to keep the
existing API unchanged. Their might be conflcits between this goal and that of
reducing the cost, and judgment calls may need to be made.

Note: when it comes to holding public keys in the PK layer, depending on how
the rest of the code is structured, it may be worth holding the key data in
memory controlled by the PK layer as opposed to a PSA key slot, moving it to a
slot only when needed (see current `ecdsa_verify_wrap` when
`MBEDTLS_USE_PSA_CRYPTO` is defined)  For example, when parsing a large
number, N, of X.509 certificates (for example the list of trusted roots), it
might be undesirable to use N PSA key slots for their public keys as long as
the certs are loaded. OTOH, this could also be addressed by merging the "X.509
parsing on-demand" (#2478), and then the public key data would be held as
bytes in the X.509 CRT structure, and only moved to a PK context / PSA slot
when it's actually used.

Note: the PK layer actually consists of two relatively distinct parts: crypto
operations, which will be covered by PSA, and parsing/writing (exporting)
from/to various formats, which is currently not fully covered by the PSA
Crypto API.

### Algorithm identifiers and other identifiers

It should be easy to provide the user with a bunch of `#define`s for algorithm
identifiers, for example `#define MBEDTLS_MD_SHA256 PSA_ALG_SHA_256`; most of
those would be in the MD, Cipher and PK compatibility layers mentioned above,
but there might be some in other modules that may be worth considering, for
example identifiers for elliptic curves.

### Lower layers

Generally speaking, we would retire all of the low-level, non-generic modules,
such as AES, SHA-256, RSA, DHM, ECDH, ECP, bignum, etc, without providing
compatibility APIs for them. People would be encouraged to switch to the PSA
API. (The compatiblity implementation of the existing PK, MD, Cipher APIs
would mostly benefit people who already used those generic APis rather than
the low-level, alg-specific ones.)

### APIs in TLS and X.509

Public APIs in TLS and X.509 may be affected by the migration in at least two
ways:

1. APIs that rely on a legacy `mbedtls_` crypto type: for example
   `mbedtls_ssl_conf_own_cert()` to configure a (certificate and the
associated) private key. Currently the private key is passed as a
`mbedtls_pk_context` object, which would probably change to a `psa_key_id_t`.
Since some users would probably still be using the compatibility PK layer, it
would need a way to easily extract the PSA key ID from the PK context.

2. APIs the accept list of identifiers: for example
   `mbedtls_ssl_conf_curves()` taking a list of `mbedtls_ecp_group_id`s. This
could be changed to accept a list of pairs (`psa_ecc_familiy_t`, size) but we
should probably take this opportunity to move to a identifier independant from
the underlying crypto implementation and use TLS-specific identifiers instead
(based on IANA values or custom enums), as is currently done in the new
`mbedtls_ssl_conf_groups()` API, see #4859).

Testing
-------

An question that needs careful consideration when we come around to removing
the low-level crypto APIs and making PK, MD and Cipher optional compatibility
layers is to be sure to preserve testing quality. A lot of the existing test
cases use the low level crypto APIs; we would need to either keep using that
API for tests, or manually migrated test to the PSA Crypto API. Perhaps a
combination of both, perhaps evolving gradually over time.
