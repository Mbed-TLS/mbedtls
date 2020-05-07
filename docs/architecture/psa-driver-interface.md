PSA Cryptoprocessor Driver Interface
====================================

This document describes an interface for cryptoprocessor drivers in the PSA cryptography API. It covers both cryptoprocessors that work with keys in cleartext (accelerators) and cryptoprocessors that work with wrapped keys or key identifiers (secure elements).

**This is work in progress**. This document is still incomplete and **may change or may be abandoned at any time**. The interface is not fully implemented in Mbed TLS yet. You can enable the experimental work in progress by setting `MBEDTLS_PSA_CRYPTO_DRIVERS` in the Mbed TLS compile-time configuration.

## Overview of cryptoprocessor drivers

### Transparent and opaque drivers

A cryptoprocessor driver is a piece of software one or more cryptographic primitive. Typically the reason to have a driver is that the primitive is implemented in hardware, and the driver is code that calls this hardware.

There are two types of cryptoprocessors, and accordingly two types of drivers.

* **Transparent** drivers implement cryptographic operations on keys that are provided in cleartext at the beginning of each operation. They are typically used for hardware **accelerators** that don't have any persistent storage. When a transparent driver is available for a particular combination of parameters (cryptographic algorithm, key type and size, etc.), it is used instead of the default software implementation.
* **Opaque** drivers implement cryptographic operations on keys that are only available inside a protected environment such as a **secure element**. For each operation, the driver receives an opaque blob which typically contains either an identifier for the key (if the key material is stored inside the secure element) or the key material in wrapped form (with the wrapping key only available inside the secure element). An opaque driver is invoked for the specific key location that the driver is registered for: the dispatch is based on the key's lifetime.

### Driver description files

To write a driver, you need to implement some functions with C linkage, and to declare these functions in a **driver description file**. The name of the functions is imposed as described below. The driver description file declares which functions the driver implements and what cryptographic mechanisms they support.

The concrete syntax for a driver description file is JSON.

A driver description is a JSON object containing at least the following elements:

* A **prefix**. This is a string which must be a valid prefix for a C identifier. All the functions provided by the driver have a name that starts with this prefix.
* A **type**: either `"transparent"` or `"opaque"`.
* A list of **capabilities**. Each capability describes a family of functions that the driver implements for a certain class of cryptographic mechanisms.

For example, here is a driver description for a driver that implements accelerated ECDSA signatures on the curve SECP256R1. The driver must provide a function `acme_sign_hash` to perform the signature calculation.

```
{
    "prefix": "acme",
    "type": "transparent",
    "capabilities": [
        {
            "functions": ["sign_hash"],
            "algorithms": [""],
            "key_types": ["PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_CURVE_SECP_R1)"],
            "key_sizes": [256]
        }
    ]
}
```

### Driver function signatures

All the functions provided by a driver have the form *prefix*`_`*function* where *prefix* is the prefix declared by the driver and *function* is the functionality that the driver implements. For example, if the driver's prefix is `acme`, the function to sign a hash is called `acme_sign_hash`.

All driver functions return a status of type `psa_status_t` which should use the error codes documented for PSA services in general and for PSA Crypto in particular.

The signature of a driver function generally looks like the signature of the PSA Crypto API that it implements, with some modifications.

* For functions that operate on a key, where the API receives a key handle, a driver function instead takes three parameters: the key attributes (`const psa_key_attributes_t*`), a pointer to the **key description** (`const uint8_t *`), and the size of the key description (`size_t`).
* TODO: key creation (opaque drivers only), operations for multipart functions, what else?

The script `scripts/psa_crypto_driver_header.py` takes a driver description file as input and generates a C header file containing the prototypes of the functions that the driver must implement.

For example, the function to sign a hash in the `acme` driver has the following prototype:
```
psa_status_t acme_sign_hash(
    const psa_key_attributes_t *attributes, const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *hash, size_t hash_length,
    uint8_t *signature, size_t signature_size, size_t *signature_length);
```

### Declaring drivers to Mbed TLS

To build Mbed TLS with drivers:

1. Activate `MBEDTLS_PSA_CRYPTO_DRIVERS` in the library configuration.

    ```
    cd /path/to/mbedtls
    scripts/config.py set MBEDTLS_PSA_CRYPTO_DRIVERS
    ```

2. Pass the [driver description files](#driver-description-files) through the Make variable `PSA_DRIVERS` when building the library.

    ```
    cd /path/to/mbedtls
    make PSA_DRIVERS="/path/to/acme/driver.json /path/to/nadir/driver.json" lib
    ```

3. Link your application with the implementation of the driver functions.

    ```
    cd /path/to/application
    ld myapp.o -L/path/to/acme -lacmedriver -L/path/to/nadir -lnadirdriver -L/path/to/mbedtls -lmbedcrypto
    ```

## How to write a transparent driver

### Key format for transparent drivers

The format of a key description for transparent drivers is the same as in applications. Refer to the documentation of `psa_export_key()` and `psa_export_public_key()`.

### Driver capabilities

A capability indicates that the driver implements a certain cryptographic mechanism or a family of related mechanism. A capability refers to one or more function, possibly restricted to certain algorithms, key types or key sizes.

TODO: some functions need to be implemented together, e.g. multipart operations

TODO: explain more

### Fallback

If a transparent driver function returns `PSA_ERROR_NOT_SUPPORTED`, the built-in software implementation will be called instead. Any other value (`PSA_SUCCESS` or a different error code) is returned to the application.

If there are multiple available transparent drivers, they are tried in turn until one returns a status other than `PSA_ERROR_NOT_SUPPORTED`.

TODO: a boolean flag in the capability indicating whether the driver fully implements the capability (and the built-in software implementation should not be used).

## How to write an opaque driver

Opaque drivers must provide at least a way to create a key and a way to destroy a key.

### Key management with key identifiers

TODO

### Key management with wrapped keys

TODO

## How to use drivers from an application

### Declaring which cryptographic mechanism an application needs

TODO: an application requirements description, broadly similar to driver capabilities.

### Using transparent drivers

Transparent drivers linked into the library are automatically used for the mechanisms that they implement.

### Using opaque drivers

Each opaque driver is assigned a location. The driver is invoked for all actions that use a key in that location. A key's location is indicated by its lifetime. The application chooses the key's lifetime when it creates the key.

For example, the following snippet creates an AES-GCM key which is only accessible inside a secure element.
```
psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(
        PSA_KEY_PERSISTENCE_DEFAULT, PSA_KEY_LOCATION_ACME_SECURE_ELEMENT));
psa_set_key_identifer(&attributes, 42);
psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
psa_set_key_size(&attributes, 128);
psa_set_key_algorithm(&attributes, PSA_ALG_GCM);
psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
psa_key_handle_t handle = 0;
psa_generate_key(&attributes, &handle);
```

TODO: how does the application know which location value to use?

## Mbed TLS internal architecture
