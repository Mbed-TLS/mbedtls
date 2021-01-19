# Mbed TLS PSA keystore format stability testing strategy

## Introduction

The PSA crypto subsystem includes a persistent key store. It is possible to create a persistent key and read it back later. This must work even if Mbed TLS has been upgraded in the meantime (except for deliberate breaks in the backward compatibility of the storage).

The goal of this document is to define a test strategy for the key store that not only validates that it's possible to load a key that was saved with the version of Mbed TLS under test, but also that it's possible to load a key that was saved with previous versions of Mbed TLS.

Interoperability is not a goal: PSA crypto implementations are not intended to have compatible storage formats. Downgrading is not required to work.

## General approach

### Limitations of a direct approach

The goal of storage format stability testing is: as a user of Mbed TLS, I want to store a key under version V and read it back under version W, with W ≥ V.

Doing the testing this way would be difficult because we'd need to have version V of Mbed TLS available when testing version W.

An alternative, semi-direct approach consists of generating test data under version V, and reading it back under version W. Done naively, this would require keeping a large amount of test data (full test coverage multiplied by the number of versions that we want to preserve backward compatibility with).

### Save-and-compare approach

Importing and saving a key is deterministic. Therefore we can ensure the stability of the storage format by creating test cases under a version V of Mbed TLS, where the test case parameters include both the parameters to pass to key creation and the expected state of the storage after the key is created. The test case creates a key as indicated by the parameters, then compares the actual state of the storage with the expected state. In addition, the test case also loads the key and checks that it has the expected data and metadata.

If the test passes with version V, this means that the test data is consistent with what the implementation does. When the test later runs under version W ≥ V, it creates and reads back a storage state which is known to be identical to the state that V would have produced. Thus, this approach validates that W can read storage states created by V.

Use a similar approach for files other than keys where possible and relevant.

### Keeping up with storage format evolution

Test cases should normally not be removed from the code base: if something has worked before, it should keep working in future versions, so we should keep testing it.

If the way certain keys are stored changes, and we don't deliberately decide to stop supporting old keys (which should only be done by retiring a version of the storage format), then we should keep the corresponding test cases in load-only mode: create a file with the expected content, load it and check the data that it contains.

## Storage architecture overview

The PSA subsystem provides storage on top of the PSA trusted storage interface. The state of the storage is a mapping from file identifer (a 64-bit number) to file content (a byte array). These files include:

* [Key files](#key-storage) (files containing one key's metadata and, except for some secure element keys, key material).
* The [random generator injected seed or state file](#random-generator-state) (`PSA_CRYPTO_ITS_RANDOM_SEED_UID`).
* [Storage transaction file](#storage-transaction-resumption).
* [Driver state files](#driver-state-files).

For a more detailed description, refer to the [Mbed Crypto storage specification](../mbed-crypto-storage-specification.md).

In addition, Mbed TLS includes an implementation of the PSA trusted storage interface on top of C stdio. This document addresses the test strategy for [PSA ITS over file](#psa-its-over-file) in a separate section below.

## Key storage testing

This section describes the desired test cases for keys created with the current storage format version. When the storage format changes, if backward compatibility is desired, old test data should be kept as described under [“Keeping up with storage format evolution”](#keeping-up-with-storage-format-evolution).

### Keystore layout

Objective: test that the key file name corresponds to the key identifier.

Method: Create a key with a given identifier (using `psa_import_key`) and verify that a file with the expected name is created, and no other. Repeat for different identifiers.

### General key format

Objective: test the format of the key file: which field goes where and how big it is.

Method: Create a key with certain metadata with `psa_import_key`. Read the file content and validate that it has the expected layout, deduced from the storage specification. Repeat with different metadata. Ensure that there are test cases covering all fields.

### Enumeration of test cases for keys

Objective: ensure that the coverage is sufficient to have assurance that all keys are stored correctly. This requires a sufficient selection of key types, sizes, policies, etc.

In particular, the tests must validate that each `PSA_xxx` constant that is stored in a key is covered by at least once test case:

* Usage flags: `PSA_KEY_USAGE_xxx`.
* Algorithms in policies: `PSA_ALG_xxx`.
* Key types: `PSA_KEY_TYPE_xxx`, `PSA_ECC_FAMILY_xxx`, `PSA_DH_FAMILY_xxx`.

Method: Each test case creates a key with `psa_import_key`, purges it from memory, then reads it back and exercises it. Generate test cases automatically based on an enumeration of available constants and some knowledge of what attributes (sizes, algorithms, …) and content to use for keys of a certain type. Note that the generated test cases will be checked into the repository (generating test cases at runtime would not allow us to test the stability of the format, only that a given version is internally consistent).

### Testing with alternative lifetime values

Objective: have test coverage for lifetimes other than the default persistent lifetime (`PSA_KEY_LIFETIME_PERSISTENT`).

Method:

* For alternative locations: have tests conditional on the presence of a driver for that location.
* For alternative persistence levels: TODO

## Random generator state

TODO

## Driver state files

Not yet implemented.

TODO

## Storage transaction resumption

Only relevant for secure element support. Not yet fully implemented.

TODO

## PSA ITS over file

TODO
