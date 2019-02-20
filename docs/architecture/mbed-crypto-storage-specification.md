Mbed Crypto storage specification
=================================

This document specifies how Mbed Crypto uses storage.

Mbed Crypto may be upgraded on an existing device with the storage preserved. Therefore:

1. Any change may break existing installations and may require an upgrade path.
1. This document retains historical information about all past released versions. Do not remove information from this document unless it has always been incorrect or it is about a version that you are sure was never released.

Mbed Crypto 0.1.0
-----------------

Tags: mbedcrypto-0.1.0b, mbedcrypto-0.1.0b2

Released in November 2018. <br>
Integrated in Mbed OS 5.11.

Supported backends:

* [PSA ITS](#file-namespace-on-its-for-0.1.0)
* [C stdio](#file-namespace-on-stdio-for-0.1.0)

Supported features:

* [Persistent transparent keys](#key-file-format-for-0.1.0) designated by a [slot number](#key-names-for-0.1.0).
* [Nonvolatile random seed](#nonvolatile-random-seed-file-format-for-0.1.0) on ITS only.

This is a beta release, and we do not promise backward compatibility, with one exception:

> On Mbed OS, if a device has a nonvolatile random seed file produced with Mbed OS 5.11.x and is upgraded to a later version of Mbed OS, the nonvolatile random seed file is preserved or upgraded.

We do not make any promises regarding key storage, or regarding the nonvolatile random seed file on other platforms.

### Key names for 0.1.0

Information about each key is stored in a dedicated file whose name is constructed from the key identifier. The way in which the file name is constructed depends on the storage backend. The content of the file is described [below](#key-file-format-for-0.1.0).

The valid values for a key identifier are the range from 1 to 0xfffeffff. This limitation on the range is not documented in user-facing documentation: according to the user-facing documentation, arbitrary 32-bit values are valid.

The code uses the following constant in an internal header (note that despite the name, this value is actually one plus the maximum permitted value):

    #define PSA_MAX_PERSISTENT_KEY_IDENTIFIER 0xffff0000

There is a shared namespace for all callers.

### Key file format for 0.1.0

All integers are encoded in little-endian order in 8-bit bytes.

The layout of a key file is:

* magic (8 bytes): `"PSA\0KEY\0"`
* version (4 bytes): 0
* type (4 bytes): `psa_key_type_t` value
* policy usage flags (4 bytes): `psa_key_usage_t` value
* policy usage algorithm (4 bytes): `psa_algorithm_t` value
* key material length (4 bytes)
* key material: output of `psa_export_key`
* Any trailing data is rejected on load.

### Nonvolatile random seed file format for 0.1.0

The nonvolatile random seed file contains a seed for the random generator. If present, it is rewritten at each boot as part of the random generator initialization.

The file format is just the seed as a byte string with no metadata or encoding of any kind.

### File namespace on ITS for 0.1.0

Assumption: ITS provides a 32-bit file identifier namespace. The Crypto service can use arbitrary file identifiers and no other part of the system accesses the same file identifier namespace.

* File 0: unused.
* Files 1 through 0xfffeffff: [content](#key-file-format-for-0.1.0) of the [key whose identifier is the file identifier](#key-names-for-0.1.0).
* File 0xffffff52 (`PSA_CRYPTO_ITS_RANDOM_SEED_UID`): [nonvolatile random seed](#nonvolatile-random-seed-file-format-for-0.1.0).
* Files 0xffff0000 through 0xffffff51, 0xffffff53 through 0xffffffff: unused.

### File namespace on stdio for 0.1.0

Assumption: C stdio, allowing names containing lowercase letters, digits and underscores, of length up to 23.

An undocumented build-time configuration value `CRYPTO_STORAGE_FILE_LOCATION` allows storing the key files in a directory other than the current directory. This value is simply prepended to the file name (so it must end with a directory separator to put the keys in a different directory).

* `CRYPTO_STORAGE_FILE_LOCATION "psa_key_slot_0"`: used as a temporary file. Must be writable. May be overwritten or deleted if present.
* `sprintf(CRYPTO_STORAGE_FILE_LOCATION "psa_key_slot_%lu", key_id)` [content](#key-file-format-for-0.1.0) of the [key whose identifier](#key-names-for-0.1.0) is `key_id`.
* Other files: unused.

Mbed Crypto 0.2.0
-----------------

**Warning:** the information in this section is provisional and may change before Mbed Crypto is released for Mbed OS 5.12. At the time of writing, we don't even know whether this version will be called 0.2.0.

To be released for Mbed OS 5.12.

Supported integrations:

* [PSA platform](#file-namespace-on-a-psa-platform-for-0.2.0)
* [library using PSA ITS](#file-namespace-on-its-as-a-library-for-0.2.0)
* [library using C stdio](#file-namespace-on-stdio-for-0.2.0)

Supported features:

* [Persistent transparent keys](#key-file-format-for-0.2.0) designated by a [key identifier and owner](#key-names-for-0.2.0).
* [Nonvolatile random seed](#nonvolatile-random-seed-file-format-for-0.2.0) on ITS only.

Backward compatibility commitments: TBD

### Key names for 0.2.0

Information about each key is stored in a dedicated file designated by a _key file identifier_ (`psa_key_file_id_t`). The key file identifier is constructed from the 32-bit key identifier (`psa_key_id_t`) and, if applicable, an identifier of the owner of the key. In integrations where there is no concept of key owner (in particular, in library integrations), the key file identifier is exactly the key identifier. When the library is integrated into a service, the service determines the semantics of the owner identifier.

The way in which the file name is constructed from the key file identifier depends on the storage backend. The content of the file is described [below](#key-file-format-for-0.2.0).

The valid values for a key identifier are the range from 1 to 0xfffeffff. This limitation on the range is not documented in user-facing documentation: according to the user-facing documentation, arbitrary 32-bit values are valid.

* Library integration: the key file name is just the key identifer. This is a 32-bit value.
* PSA service integration: the key file identifier is `(uint32_t)owner_uid << 32 | key_id` where `key_id` is the key identifier specified by the application and `owner_uid` (of type `int32_t`) is the calling partition identifier provided to the server by the partition manager. This is a 64-bit value.

### Key file format for 0.2.0

The layout is identical to [0.1.0](#key-file-format-for-0.1.0) so far. However note that the encoding of key types, algorithms and key material has changed, therefore the storage format is not compatible (despite using the same value in the version field so far).

### Nonvolatile random seed file format for 0.2.0

[Identical to 0.1.0](#nonvolatile-random-seed-file-format-for-0.1.0).

### File namespace on a PSA platform for 0.2.0

Assumption: ITS provides a 64-bit file identifier namespace. The Crypto service can use arbitrary file identifiers and no other part of the system accesses the same file identifier namespace.

Assumption: the owner identifier is a nonzero value of type `int32_t`.

* Files 0 through 0xffffff51, 0xffffff53 through 0xffffffff: unused, reserved for internal use of the crypto library or crypto service.
* File 0xffffff52 (`PSA_CRYPTO_ITS_RANDOM_SEED_UID`): [nonvolatile random seed](#nonvolatile-random-seed-file-format-for-0.1.0).
* Files 0x100000000 through 0xffffffffffff: [content](#key-file-format-for-0.2.0) of the [key whose identifier is the file identifier](#key-names-for-0.2.0). The upper 32 bits determine the owner.

### File namespace on ITS as a library for 0.2.0

Assumption: ITS provides a 64-bit file identifier namespace. The entity using the crypto library can use arbitrary file identifiers and no other part of the system accesses the same file identifier namespace.

This is a library integration, so there is no owner. The key file identifier is identical to the key identifier.

* File 0: unused.
* Files 1 through 0xfffeffff: [content](#key-file-format-for-0.2.0) of the [key whose identifier is the file identifier](#key-names-for-0.2.0).
* File 0xffffff52 (`PSA_CRYPTO_ITS_RANDOM_SEED_UID`): [nonvolatile random seed](#nonvolatile-random-seed-file-format-for-0.2.0).
* Files 0xffff0000 through 0xffffff51, 0xffffff53 through 0xffffffff, 0x100000000 through 0xffffffffffffffff: unused.

### File namespace on stdio for 0.2.0

This is a library integration, so there is no owner. The key file identifier is identical to the key identifier.

[Identical to 0.1.0](#file-namespace-on-stdio-for-0.1.0).

### Upgrade from 0.1.0 to 0.2.0.

* Delete files 1 through 0xfffeffff, which contain keys in a format that is no longer supported.

### Suggested changes to make before 0.2.0

The library integration and the PSA platform integration use different sets of file names. This is annoyingly non-uniform. For example, if we want to store non-key files, we have room in different ranges (0 through 0xffffffff on a PSA platform, 0xffff0000 through 0xffffffffffffffff in a library integration).

It would simplify things to always have a 32-bit owner, with a nonzero value, and thus reserve the range 0–0xffffffff for internal library use.
