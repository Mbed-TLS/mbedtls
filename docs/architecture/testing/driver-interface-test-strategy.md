# Mbed TLS driver interface test strategy

This document describes the test strategy for the driver interfaces in Mbed TLS. Mbed TLS has interfaces for secure element drivers, accelerator drivers and entropy drivers. This document is about testing Mbed TLS itself; testing drivers is out of scope.

The driver interfaces are standardized through PSA Cryptography functional specifications.

## Secure element driver interface testing

### Secure element driver interfaces

#### Opaque driver interface

The [unified driver interface](../../proposed/psa-driver-interface.md) supports both transparent drivers (for accelerators) and opaque drivers (for secure elements).

Drivers exposing this interface need to be registered at compile time by declaring their JSON description file.

#### Dynamic secure element driver interface

The dynamic secure element driver interface (SE interface for short) is defined by [`psa/crypto_se_driver.h`](../../../include/psa/crypto_se_driver.h). This is an interface between Mbed TLS and one or more third-party drivers.

The SE interface consists of one function provided by Mbed TLS (`psa_register_se_driver`) and many functions that drivers must implement. To make a driver usable by Mbed TLS, the initialization code must call `psa_register_se_driver` with a structure that describes the driver. The structure mostly contains function pointers, pointing to the driver's methods. All calls to a driver function are triggered by a call to a PSA crypto API function.

### SE driver interface unit tests

This section describes unit tests that must be implemented to validate the secure element driver interface. Note that a test case may cover multiple requirements; for example a “good case” test can validate that the proper function is called, that it receives the expected inputs and that it produces the expected outputs.

Many SE driver interface unit tests could be covered by running the existing API tests with a key in a secure element.

#### SE driver registration

This applies to dynamic drivers only.

* Test `psa_register_se_driver` with valid and with invalid arguments.
* Make at least one failing call to `psa_register_se_driver` followed by a successful call.
* Make at least one test that successfully registers the maximum number of drivers and fails to register one more.

#### Dispatch to SE driver

For each API function that can lead to a driver call (more precisely, for each driver method call site, but this is practically equivalent):

* Make at least one test with a key in a secure element that checks that the driver method is called. A few API functions involve multiple driver methods; these should validate that all the expected driver methods are called.
* Make at least one test with a key that is not in a secure element that checks that the driver method is not called.
* Make at least one test with a key in a secure element with a driver that does not have the requisite method (i.e. the method pointer is `NULL`) but has the substructure containing that method, and check that the return value is `PSA_ERROR_NOT_SUPPORTED`.
* Make at least one test with a key in a secure element with a driver that does not have the substructure containing that method (i.e. the pointer to the substructure is `NULL`), and check that the return value is `PSA_ERROR_NOT_SUPPORTED`.
* At least one test should register multiple drivers with a key in each driver and check that the expected driver is called. This does not need to be done for all operations (use a white-box approach to determine if operations may use different code paths to choose the driver).
* At least one test should register the same driver structure with multiple lifetime values and check that the driver receives the expected lifetime value.

Some methods only make sense as a group (for example a driver that provides the MAC methods must provide all or none). In those cases, test with all of them null and none of them null.

#### SE driver inputs

For each API function that can lead to a driver call (more precisely, for each driver method call site, but this is practically equivalent):

* Wherever the specification guarantees parameters that satisfy certain preconditions, check these preconditions whenever practical.
* If the API function can take parameters that are invalid and must not reach the driver, call the API function with such parameters and verify that the driver method is not called.
* Check that the expected inputs reach the driver. This may be implicit in a test that checks the outputs if the only realistic way to obtain the correct outputs is to start from the expected inputs (as is often the case for cryptographic material, but not for metadata).

#### SE driver outputs

For each API function that leads to a driver call, call it with parameters that cause a driver to be invoked and check how Mbed TLS handles the outputs.

* Correct outputs.
* Incorrect outputs such as an invalid output length.
* Expected errors (e.g. `PSA_ERROR_INVALID_SIGNATURE` from a signature verification method).
* Unexpected errors. At least test that if the driver returns `PSA_ERROR_GENERIC_ERROR`, this is propagated correctly.

Key creation functions invoke multiple methods and need more complex error handling:

* Check the consequence of errors detected at each stage (slot number allocation or validation, key creation method, storage accesses).
* Check that the storage ends up in the expected state. At least make sure that no intermediate file remains after a failure.

#### Persistence of SE keys

The following tests must be performed at least one for each key creation method (import, generate, ...).

* Test that keys in a secure element survive `psa_close_key(); psa_open_key()`.
* Test that keys in a secure element survive `mbedtls_psa_crypto_free(); psa_crypto_init()`.
* Test that the driver's persistent data survives `mbedtls_psa_crypto_free(); psa_crypto_init()`.
* Test that `psa_destroy_key()` does not leave any trace of the key.

#### Resilience for SE drivers

Creating or removing a key in a secure element involves multiple storage modifications (M<sub>1</sub>, ..., M<sub>n</sub>). If the operation is interrupted by a reset at any point, it must be either rolled back or completed.

* For each potential interruption point (before M<sub>1</sub>, between M<sub>1</sub> and M<sub>2</sub>, ..., after M<sub>n</sub>), call `mbedtls_psa_crypto_free(); psa_crypto_init()` at that point and check that this either rolls back or completes the operation that was started.
* This must be done for each key creation method and for key destruction.
* This must be done for each possible flow, including error cases (e.g. a key creation that fails midway due to `OUT_OF_MEMORY`).
* The recovery during `psa_crypto_init` can itself be interrupted. Test those interruptions too.
* Two things need to be tested: the key that is being created or destroyed, and the driver's persistent storage.
* Check both that the storage has the expected content (this can be done by e.g. using a key that is supposed to be present) and does not have any unexpected content (for keys, this can be done by checking that `psa_open_key` fails with `PSA_ERROR_DOES_NOT_EXIST`).

This requires instrumenting the storage implementation, either to force it to fail at each point or to record successive storage states and replay each of them. Each `psa_its_xxx` function call is assumed to be atomic.

### SE driver system tests

#### Real-world use case

We must have at least one driver that is close to real-world conditions:

* With its own source tree.
* Running on actual hardware.
* Run the full driver validation test suite (which does not yet exist).
* Run at least one test application (e.g. the Mbed OS TLS example).

This requirement shall be fulfilled by the [Microchip ATECC508A driver](https://github.com/ARMmbed/mbed-os-atecc608a/).

#### Complete driver

We should have at least one driver that covers the whole interface:

* With its own source tree.
* Implementing all the methods.
* Run the full driver validation test suite (which does not yet exist).

A PKCS#11 driver would be a good candidate. It would be useful as part of our product offering.

## Unified driver interface testing

The [unified driver interface](../../proposed/psa-driver-interface.md) defines interfaces for accelerators.

### Test requirements

#### Requirements for transparent driver testing

Every cryptographic mechanism for which a transparent driver interface exists (key creation, cryptographic operations, …) must be exercised in at least one build. The test must verify that the driver code is called.

#### Requirements for fallback

The driver interface includes a fallback mechanism so that a driver can reject a request at runtime and let another driver handle the request. For each entry point, there must be at least three test runs with two or more drivers available with driver A configured to fall back to driver B, with one run where A returns `PSA_SUCCESS`, one where A returns `PSA_ERROR_NOT_SUPPORTED` and B is invoked, and one where A returns a different error and B is not invoked.

### Test drivers

We have test drivers that are enabled by `PSA_CRYPTO_DRIVER_TEST` (not present
in the usual config files, must be defined on the command line or in a custom
config file). Those test drivers are implemented in `tests/src/drivers/*.c`
and their API is declared in `tests/include/test/drivers/*.h`.

We have two test driver registered: `mbedtls_test_opaque_driver` and
`mbedtls_test_transparent_driver`. These are described in
`scripts/data_files/driver_jsons/mbedtls_test_xxx_driver.json` (as much as our
JSON support currently allows). Each of the drivers can potentially implement
support for several mechanism; conversely, each of the file mentioned in the
previous paragraph can potentially contribute to both the opaque and the
transparent test driver.

Each entry point is instrumented to record the number of hits for each part of
the driver (same division as the files) and the status of the last call. It is
also possible to force the next call to return a specified status, and
sometimes more things can be forced: see the various
`mbedtls_test_driver_XXX_hooks_t` structures declared by each driver (and
subsections below).

The drivers can use one of two back-ends:
- internal: this requires the built-in implementation to be present.
- libtestdriver1: this allows the built-in implementation to be omitted from
  the build.

Historical note: internal was initially the only back-end; then support for
libtestdriver1 was added gradually. Support for libtestdriver1 is now complete
(see following sub-sections), so we could remove internal now. Note it's
useful to have builds with both a driver and the built-in, in order to test
fallback to built-in, which is currently done only with internal, but this can
be achieved with libtestdriver1 just as well.

Note on instrumentation: originally, when only the internal backend was
available, hits were how we knew that the driver was called, as opposed to
directly calling the built-in code. With libtestdriver1, we can check that by
ensuring that the built-in code is not present, so if the operation gives the
correct result, only a driver call can have calculated that result. So,
nowadays there is low value in checking the hit count. There is still some
value for hit counts, e.g. checking that we don't call a multipart entry point
when we intended to call the one-shot entry point, but it's limited.

Note: our test drivers tend to provide all possible entry points (with a few
exceptions that may not be intentional, see the next sections). However, in
some cases, when an entry point is not available, the core is supposed to
implement it using other entry points, for example:
- `mac_verify` may use `mac_compute` if the driver does no provide verify;
- for things that have both one-shot and multi-part API, the driver can
  provide only the multi-part entry points, and the core is supposed to
implement one-shot on top of it (but still call the one-shot entry points when
they're available);
- `sign/verify_message` can be implemented on top of `sign/verify_hash` for
  some algorithms;
- (not sure if the list is exhaustive).

Ideally, we'd want build options for the test drivers so that we can test with
different combinations of entry points present, and make sure the core behaves
appropriately when some entry points are absent but other entry points allow
implementing the operation. This will remain hard to test until we have proper
support for JSON-defined drivers with auto-generation of dispatch code.
(The `MBEDTLS_PSA_ACCEL_xxx` macros we currently use are not expressive enough
to specify which entry points are supported for a given mechanism.)

Our implementation of PSA Crypto is structured in a way that the built-in
implementation of each operation follows the driver API, see
[`../architecture/psa-crypto-implementation-structure.md`](../architecture/psa-crypto-implementation-structure.html).
This makes implementing the test drivers very easy: each entry point has a
corresponding `mbedtls_psa_xxx()` function that it can call as its
implementation - with the `libtestdriver1` back-end the function is called
`libtestdriver1_mbedtls_psa_xxx()` instead.

A nice consequence of that strategy is that when an entry point has
test-driver support, most of the time, it automatically works for all
algorithms and key types supported by the library. (The exception being when
the driver needs to call a different function for different key types, as is
the case with some asymmetric key management operations.) (Note: it's still
useful to test drivers in configurations with partial algorithm support, and
that can still be done by configuring libtestdriver1 and the main library as
desired.)

The renaming process for `libtestdriver1` is implemented as a few Perl regexes
applied to a copy of the library code, see the `libtestdriver1.a` target in
`tests/Makefile`. Another modification that's done to this copy is appending
`tests/include/test/drivers/crypto_config_test_driver_extension.h` to
`psa/crypto_config.h`. This file reverses the `ACCEL`/`BUILTIN` macros so that
`libtestdriver1` includes as built-in what the main `libmbedcrypto.a` will
have accelerated; see that file's initial comment for details. See also
`helper_libtestdriver1_` functions and the preceding comment in `all.sh` for
how libtestdriver is used in practice.

This general framework needs specific code for each family of operations. At a
given point in time, not all operations have the same level of support. The
following sub-sections describe the status of the test driver support, mostly
following the structure and order of sections 9.6 and 10.2 to 10.10 of the
[PSA Crypto standard](https://arm-software.github.io/psa-api/crypto/1.1/) as
that is also a natural division for implementing test drivers (that's how the
code is divided into files).

#### Key management

The following entry points are declared in `test/drivers/key_management.h`:

- `"init"` (transparent and opaque)
- `"generate_key"` (transparent and opaque)
- `"export_public_key"` (transparent and opaque)
- `"import_key"` (transparent and opaque)
- `"export_key"` (opaque only)
- `"get_builtin_key"` (opaque only)
- `"copy_key"` (opaque only)

The transparent driver fully implements the declared entry points, and can use
any backend: internal or libtestdriver1.

The opaque's driver implementation status is as follows:
- `"generate_key"`: not implemented, always returns `NOT_SUPPORTED`.
- `"export_public_key"`: implemented only for ECC and RSA keys, both backends.
- `"import_key"`: implemented except for DH keys, both backends.
- `"export_key"`: implemented for built-in keys (ECC and AES), and for
  non-builtin keys except DH keys. (Backend not relevant.)
- `"get_builtin_key"`: implemented - provisioned keys: AES-128 and ECC
  secp2456r1. (Backend not relevant.)
- `"copy_key"`: implemented - emulates a SE without storage. (Backend not
  relevant.)

Note: the `"init"` entry point is not part of the "key management" family, but
listed here as it's declared and implemented in the same file. With the
transparent driver and the libtestdriver1 backend, it calls
`libtestdriver1_psa_crypto_init()`, which partially but not fully ensures
that this entry point is called before other entry points in the test drivers.
With the opaque driver, this entry point just does nothing an returns success.

The following entry points are defined by the driver interface but missing
from our test drivers:
- `"allocate_key"`, `"destroy_key"`: this is for opaque drivers that store the
  key material internally.

Note: the instrumentation also allows forcing the output and its length.

#### Message digests (Hashes)

The following entry points are declared (transparent only):
- `"hash_compute"`
- `"hash_setup"`
- `"hash_clone"`
- `"hash_update"`
- `"hash_finish"`
- `"hash_abort"`

The transparent driver fully implements the declared entry points, and can use
any backend: internal or libtestdriver1.

This familly is not part of the opaque driver as it doesn't use keys.

#### Message authentication codes (MAC)

The following entry points are declared (transparent and opaque):
- `"mac_compute"`
- `"mac_sign_setup"`
- `"mac_verify_setup"`
- `"mac_update"`
- `"mac_sign_finish"`
- `"mac_verify_finish"`
- `"mac_abort"`

The transparent driver fully implements the declared entry points, and can use
any backend: internal or libtestdriver1.

The opaque driver only implements the instrumentation but not the actual
operations: entry points will always return `NOT_SUPPORTED`, unless another
status is forced.

The following entry points are not implemented:
- `mac_verify`: this mostly makes sense for opaque drivers; the core will fall
  back to using `"mac_compute"` if this is not implemented. So, perhaps
ideally we should test both with `"mac_verify"` implemented and with it not
implemented? Anyway, we have a test gap here.

#### Unauthenticated ciphers

The following entry points are declared (transparent and opaque):
- `"cipher_encrypt"`
- `"cipher_decrypt"`
- `"cipher_encrypt_setup"`
- `"cipher_decrypt_setup"`
- `"cipher_set_iv"`
- `"cipher_update"`
- `"cipher_finish"`
- `"cipher_abort"`

The transparent driver fully implements the declared entry points, and can use
any backend: internal or libtestdriver1.

The opaque driver is not implemented at all, neither instumentation nor the
operation: entry points always return `NOT_SUPPORTED`.

Note: the instrumentation also allows forcing a specific output and output
length.

#### Authenticated encryption with associated data (AEAD)

The following entry points are declared (transparent only):
- `"aead_encrypt"`
- `"aead_decrypt"`
- `"aead_encrypt_setup"`
- `"aead_decrypt_setup"`
- `"aead_set_nonce"`
- `"aead_set_lengths"`
- `"aead_update_ad"`
- `"aead_update"`
- `"aead_finish"`
- `"aead_verify"`
- `"aead_abort"`

The transparent driver fully implements the declared entry points, and can use
any backend: internal or libtestdriver1.

The opaque driver does not implement or even declare entry points for this
family.

Note: the instrumentation records the number of hits per entry point, not just
the total number of hits for this family.

#### Key derivation

Not covered at all by the test drivers.

That's a test gap which reflects a feature gap: the driver interface does
define a key derivation family of entry points, but we don't currently
implement that part of the driver interface, see #5488 and related issues.

#### Asymmetric signature

The following entry points are declared (transparent and opaque):

- `"sign_message"`
- `"verify_message"`
- `"sign_hash"`
- `"verify_hash"`

The transparent driver fully implements the declared entry points, and can use
any backend: internal or libtestdriver1.

The opaque driver is not implemented at all, neither instumentation nor the
operation: entry points always return `NOT_SUPPORTED`.

Note: the instrumentation also allows forcing a specific output and output
length, and has two instance of the hooks structure: one for sign, the other
for verify.

Note: when a driver implements only the `"xxx_hash"` entry points, the core is
supposed to implement the `psa_xxx_message()` functions by computing the hash
itself before calling the `"xxx_hash"` entry point. Since the test driver does
implement the `"xxx_message"` entry point, it's not exercising that part of
the core's expected behaviour.

#### Asymmetric encryption

The following entry points are declared (transparent and opaque):

- `"asymmetric_encrypt"`
- `"asymmetric_decrypt"`

The transparent driver fully implements the declared entry points, and can use
any backend: internal or libtestdriver1.

The opaque driver implements the declared entry points, and can use any
backend: internal or libtestdriver1. However it does not implement the
instrumentation (hits, forced output/status), as this [was not an immediate
priority](https://github.com/Mbed-TLS/mbedtls/pull/8700#issuecomment-1892466159).

Note: the instrumentation also allows forcing a specific output and output
length.

#### Key agreement

The following entry points are declared (transparent and opaque):

- `"key_agreement"`

The transparent driver fully implements the declared entry points, and can use
any backend: internal or libtestdriver1.

The opaque driver is not implemented at all, neither instumentation nor the
operation: entry points always return `NOT_SUPPORTED`.

Note: the instrumentation also allows forcing a specific output and output
length.

#### Other cryptographic services (Random number generation)

Not covered at all by the test drivers.

The driver interface defines a `"get_entropy"` entry point, as well as a
"Random generation" family of entry points. None of those are currently
implemented in the library. Part of it will be planned for 4.0, see #8150.

#### PAKE extension

The following entry points are declared (transparent only):
- `"pake_setup"`
- `"pake_output"`
- `"pake_input"`
- `"pake_get_implicit_key"`
- `"pake_abort"`

Note: the instrumentation records hits per entry point and allows forcing the
output and its length, as well as forcing the status of setup independently
from the others.

The transparent driver fully implements the declared entry points, and can use
any backend: internal or libtestdriver1.

The opaque driver does not implement or even declare entry points for this
family.

### Driver wrapper test suite

We have a test suite dedicated to driver dispatch, which takes advantage of the
instrumentation in the test drivers described in the previous section, in
order to check that drivers are called when they're supposed to, and that the
core behaves as expected when they return errors (in particular, that we fall
back to the built-in implementation when the driver returns `NOT_SUPPORTED`).

This is `test_suite_psa_crypto_driver_wrappers`, which is maintained manually
(that is, the test cases in the `.data` files are not auto-generated). The
entire test suite depends on the test drivers being enabled
(`PSA_CRYPTO_DRIVER_TEST`), which is not the case in the default or full
config.

The test suite is focused on driver usage (mostly by checking the expected
number of hits) but also does some validation of the results: for
deterministic algorithms, known-answers tests are used, and for the rest, some
consistency checks are done (more or less detailled depending on the algorithm
and build configuration).

#### Configurations coverage

The driver wrappers test suite has cases that expect both the driver and the
built-in to be present, and also cases that expect the driver to be present
but not the built-in. As such, it's impossible for a single configuration to
run all test cases, and we need at least two: driver+built-in, and
driver-only.

- The driver+built-in case is covered by `test_psa_crypto_drivers` in `all.sh`.
This covers all areas (key types and algs) at once.
- The driver-only case is split into multiple `all.sh` components whose names
  start with `test_psa_crypto_config_accel`; we have one or more component per
area, see below.

Here's a summary of driver-only coverage, grouped by families of key types.

Hash (key types: none)
- `test_psa_crypto_config_accel_hash`: all algs, default config, no parity
  testing.
- `test_psa_crypto_config_accel_hash_use_psa`: all algs, full config, with
  parity testing.

HMAC (key type: HMAC)
- `test_psa_crypto_config_accel_hmac`: all algs, full config except a few
  exclusions (PKCS5, PKCS7, HMAC-DRBG, legacy HKDF, deterministic ECDSA), with
parity testing.

Cipher, AEAD and CMAC (key types: DES, AES, ARIA, CHACHA20, CAMELLIA):
- `test_psa_crypto_config_accel_cipher_aead_cmac`: all key types and algs, full
  config with a few exclusions (NIST-KW), with parity testing.
- `test_psa_crypto_config_accel_des`: only DES (with all algs), full
  config, no parity testing.
- `test_psa_crypto_config_accel_aead`: only AEAD algs (with all relevant key
  types), full config, no parity testing.

Key derivation (key types: `DERIVE`, `RAW_DATA`, `PASSWORD`, `PEPPER`,
`PASSWORD_HASH`):
- No testing as we don't have driver support yet (see previous section).

RSA (key types: `RSA_KEY_PAIR_xxx`, `RSA_PUBLIC_KEY`):
- `test_psa_crypto_config_accel_rsa_crypto`: all 4 algs (encryption &
  signature, v1.5 & v2.1), config `crypto_full`, with parity testing excluding
PK.

DH (key types: `DH_KEY_PAIR_xxx`, `DH_PUBLIC_KEY`):
- `test_psa_crypto_config_accel_ffdh`: all key types and algs, full config,
  with parity testing.
- `test_psa_crypto_config_accel_ecc_ffdh_no_bignum`: with also bignum removed.

ECC (key types: `ECC_KEY_PAIR_xxx`, `ECC_PUBLIC_KEY`):
- Single algorithm accelerated (both key types, all curves):
  - `test_psa_crypto_config_accel_ecdh`: default config, no parity testing.
  - `test_psa_crypto_config_accel_ecdsa`: default config, no parity testing.
  - `test_psa_crypto_config_accel_pake`: full config, no parity testing.
- All key types, algs and curves accelerated (full config with exceptions,
  with parity testing):
  - `test_psa_crypto_config_accel_ecc_ecp_light_only`: `ECP_C` mostly disabled
  - `test_psa_crypto_config_accel_ecc_no_ecp_at_all`: `ECP_C` fully disabled
  - `test_psa_crypto_config_accel_ecc_no_bignum`: `BIGNUM_C` disabled (DH disabled)
  - `test_psa_crypto_config_accel_ecc_ffdh_no_bignum`: `BIGNUM_C` disabled (DH accelerated)
- Other - all algs accelerated but only some algs/curves (full config with
  exceptions, no parity testing):
  - `test_psa_crypto_config_accel_ecc_some_key_types`
  - `test_psa_crypto_config_accel_ecc_non_weierstrass_curves`
  - `test_psa_crypto_config_accel_ecc_weierstrass_curves`

Note: `analyze_outcomes.py` provides a list of test cases that are not
executed in any configuration tested on the CI. We're missing driver-only HMAC
testing, but no test is flagged as never executed there; this reveals we don't
have "fallback not available" cases for MAC, see #8565.

#### Test case coverage

Since `test_suite_psa_crypto_driver_wrappers.data` is maintained manually,
we need to make sure it exercises all the cases that need to be tested. In the
future, this file should be generated in order to ensure exhaustiveness.

In the meantime, one way to observe (lack of) completeness is to look at line
coverage in test driver implementaitons - this doesn't reveal all gaps, but it
does reveal cases where we thought about something when writing the test
driver, but not when writing test functions/data.

Key management:
- `mbedtls_test_transparent_generate_key()` is not tested with RSA keys.
- `mbedtls_test_transparent_import_key()` is not tested with DH keys.
- `mbedtls_test_opaque_import_key()` is not tested with unstructured keys nor
  with RSA keys (nor DH keys since that's not implemented).
- `mbedtls_test_opaque_export_key()` is not tested with non-built-in keys.
- `mbedtls_test_transparent_export_public_key()` is not tested with RSA or DH keys.
- `mbedtls_test_opaque_export_public_key()` is not tested with non-built-in keys.
- `mbedtls_test_opaque_copy_key()` is not tested at all.

Hash:
- `mbedtls_test_transparent_hash_finish()` is not tested with a forced status.

MAC:
- The following are not tested with a forced status:
  - `mbedtls_test_transparent_mac_sign_setup()`
  - `mbedtls_test_transparent_mac_verify_setup()`
  - `mbedtls_test_transparent_mac_update()`
  - `mbedtls_test_transparent_mac_verify_finish()`
  - `mbedtls_test_transparent_mac_abort()`
- No opaque entry point is tested (they're not implemented either).

Cipher:
- The following are not tested with a forced status nor with a forced output:
  - `mbedtls_test_transparent_cipher_encrypt()`
  - `mbedtls_test_transparent_cipher_finish()`
- No opaque entry point is tested (they're not implemented either).

AEAD:
- The following are not tested with a forced status:
  - `mbedtls_test_transparent_aead_set_nonce()`
  - `mbedtls_test_transparent_aead_set_lengths()`
  - `mbedtls_test_transparent_aead_update_ad()`
  - `mbedtls_test_transparent_aead_update()`
  - `mbedtls_test_transparent_aead_finish()`
  - `mbedtls_test_transparent_aead_verify()`
- `mbedtls_test_transparent_aead_verify()` is not tested with an invalid tag
  (though it might be in another test suite).

Signature:
- `sign_hash()` is not tested with RSA-PSS
- No opaque entry point is tested (they're not implemented either).

Key agreement:
- `mbedtls_test_transparent_key_agreement()` is not tested with FFDH.
- No opaque entry point is tested (they're not implemented either).

PAKE:
- All lines are covered.
