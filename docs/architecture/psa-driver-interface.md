PSA Cryptoprocessor Driver Interface
====================================

This document describes an interface for cryptoprocessor drivers in the PSA cryptography API. It describes the design of the PSA interface as well as the reference implementation in Mbed TLS and provides instructions and guidelines to driver writers.

**This is work in progress**. This document is still incomplete and **may change or may be abandoned at any time**. The interface is not fully implemented in Mbed TLS yet and is disabled by default; you can enable the experimental work in progress by setting `MBEDTLS_PSA_CRYPTO_DRIVERS` in the compile-time configuration.

## Introduction

### Purpose of the driver interface

The PSA Cryptography API defines an interface that allows applications to perform cryptographic operations in a uniform way regardless of how the operations are performed. Under the hood, different keys may be processed in different hardware or in different logical partitions, and different algorithms may involve different hardware or software components.

The driver interface allows implementations of the PSA Crypytography API to be built compositionally. An implementation of the PSA Cryptography API is composed of a **core** and zero or more **drivers**. The core handles key management, enforces key usage policies, and dispatches cryptographic operations either to the applicable driver or to built-in code.

Functions in the PSA Cryptography API invoke functions in the core. Code from the core calls drivers as described in the present document.

### Types of drivers

The PSA Cryptography driver interface supports three types of cryptoprocessors, and accordingly three types of drivers.

* **Transparent** drivers implement cryptographic operations on keys that are provided in cleartext at the beginning of each operation. They are typically used for hardware **accelerators** that don't have any persistent storage. When a transparent driver is available for a particular combination of parameters (cryptographic algorithm, key type and size, etc.), it is used instead of the default software implementation.
* **Opaque** drivers implement cryptographic operations on keys that can only be used inside a protected environment such as a **secure element without storage**. The code that calls the driver only sees the key in an wrapped form which only the protected environment can decrypt. For each operation, the driver receives an opaque blob containing the key material in wrapped form. An opaque driver is invoked for the specific key location that the driver is registered for: the dispatch is based on the key's lifetime.
* **Remote** drivers implement cryptographic operations on keys that are fully stored inside a protected environment such as a **secure element with storage**. The code that calls the driver passes it a label or identifier to indicate which key to use. A remote opaque driver is invoked for the specific key location that the driver is registered for: the dispatch is based on the key's lifetime.

## Overview of drivers

### Deliverables for a driver

To write a driver, you need to implement some functions with C linkage, and to declare these functions in a **driver description file**. The driver description file declares which functions the driver implements and what cryptographic mechanisms they support. Depending on the driver type, you may also need to define some C types in a header file.

The concrete syntax for a driver description file is JSON. The structure of this JSON file is specified in the section [“Driver description syntax”](#driver-description-syntax).

A driver therefore consists of:

* A driver description file (in JSON format).
* C header files defining the types required by the driver description. The names of these header files is declared in the driver description file.
* An object file compiled for the target platform defining the functions required by the driver description. Implementations may allow drivers to be provided as source files and compiled with the core instead of being pre-compiled.

How to provide the driver description file, the C header files and the object code is implementation-dependent.

Implementations should support multiple drivers.

### Driver description syntax

The concrete syntax for a driver description file is JSON.

#### Driver description top-level element

A driver description is a JSON object containing the following properties:

* `"prefix"` (mandatory, string). This must be a valid prefix for a C identifier. All the types and functions provided by the driver have a name that starts with this prefix unless overridden with a `"name"` element in the applicable capability as described below.
* `"type"` (mandatory, string). One of `"transparent"`, `"opaque"` or `"remote"`.
* `"headers"` (optional, array of strings). A list of header files. These header files must define the types provided by the driver and may declare the functions provided by the driver. They may include other PSA headers and standard headers of the platform. Whether they may include other headers is implementation-specific. If omitted, the list of headers is empty.
* `"capabilities"` (mandatory, array of [capabilities](#driver-description-capability)).
A list of **capabilities**. Each capability describes a family of functions that the driver implements for a certain class of cryptographic mechanisms.

#### Driver description capability

A capability declares a family of functions that the driver implements for a certain class of cryptographic mechanisms. The capability specifies which key types and algorithms are covered and the names of the types and functions that implement it.

A capability is a JSON object containing the following properties:

* `"methods"` (mandatory, list of strings). A list of method names. Most method names consist of PSA API function names without the `psa_` prefix. The exact set of method names that a driver may define depends on the driver type; refer to the section on each driver type for details.
* `"algorithms"` (optional, list of strings). Each element is an [algorithm specification](#algorithm-specifications). If specified, the core will invoke the methods listed in the `"methods"` property only when performing one of the specified algorithms. If omitted, the core will invoke the methods for all applicable algorithms.
* `"key_types"` (optional, list of strings). Each element is a [key type specification](#key-type-specifications). If specified, the core will invoke the methods listed in the `"methods"` property only for operations involving a key with one of the specified key types. If omitted, the core will invoke the methods for all applicable key types.
* `"key_sizes"` (optional, list of integers). If specified, the core will invoke the methods listed in the `"methods"` property only for operations involving a key with one of the specified key sizes. If omitted, the core will invoke the methods for all applicable key sizes. Key sizes are expressed in bits.
* `"names"` (optional, object). A mapping from method names listed in the `"methods"` value, to the name of the C function in the driver that implements this method. If a method is not listed here, name of the driver function that implements it is the driver's prefix followed by an underscore (`_`) followed by the method name. If this property is omitted, it is equivalent to an empty object (so each method is implemented by a function with called *prefix*`_`*method*).
* `"fallback"` (optional for transparent drivers, not permitted for opaque or remote drivers, boolean). If present and true, the driver may return `PSA_ERROR_NOT_SUPPORTED`, in which case the core should call another driver or use built-in code to perform this operation. If absent or false, the core should not include built-in code to perform this particular cryptographic mechanism.

Example: the following capability declares that the driver can perform deterministic ECDSA signatures using SHA-256 or SHA-384 with a SECP256R1 or SECP384R1 private key (with either hash being possible in combinatio with either curve). If the prefix of this driver is `"acme"`, the function that performs the signature is called `acme_sign_hash`.
```
{
    "functions": ["sign_hash"],
    "algorithms": ["PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256)",
                   "PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_384)"],
    "key_types": ["PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_CURVE_SECP_R1)"],
    "key_sizes": [256, 384]
}
```

#### Algorithm specifications

An algorithm specification is a string consisting of a `PSA_ALG_xxx` macro that specifies a cryptographic algorithm defined by the PSA Cryptography API. If the macro takes arguments, the string must have the syntax of a C macro call and each argument must be an algorithm specification or a decimal or hexadecimal literal with no suffix, depending on the expected type of argument.

Spaces are optional after commas. Whether other whitespace is permitted is implementation-specific.

Valid examples:
```
PSA_ALG_SHA_256
PSA_ALG_HMAC(PSA_ALG_SHA_256)
PSA_ALG_KEY_AGREEMENT(PSA_ALG_ECDH, PSA_ALG_HKDF(PSA_ALG_SHA_256))
```

#### Key type specifications

An algorithm specification is a string consisting of a `PSA_KEY_TYPE_xxx` macro that specifies a key type defined by the PSA Cryptography API. If the macro takes an argument, the string must have the syntax of a C macro call and each argument must be the name of a constant of suitable type (curve or group).

The name `_` may be used instead of a curve or group to indicate that the capability concerns all curves or groups.

Valid examples:
```
PSA_KEY_TYPE_AES
PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_CURVE_SECP_R1)
PSA_KEY_TYPE_ECC_KEY_PAIR(_)
```

### Driver methods

A **method** in a driver is a function that implements an aspect of a capability of a driver. Most methods correspond to a particular function in the PSA Cryptography API. For example, if a call to `psa_sign_hash()` is dispatched to a driver, it invokes the driver's `sign_hash` method.

All driver functions return a status of type `psa_status_t` which should use the error codes documented for PSA services in general and for PSA Crypto in particular.

The signature of a driver function generally looks like the signature of the PSA Crypto API that it implements, with some modifications. This section gives an overview of modifications that apply to whole classes of functions. Refer to the reference section for each driver type for details.

* For functions that operate on an existing key, the `psa_key_id_t` parameter (`psa_key_handle_t` in versions of Mbed TLS that are compatible with PSA Crypto 1.0 beta 3) is replaced by a sequence of parameters that describe the key. The first of these parameters is always the key attributes (`const psa_key_attributes_t *`). The subsequent parameters depend on the driver type:
    * For a transparent driver, the key material (`const uint8_t *`), and its size in bytes (`size_t`). The format of the key material is the same export format as for `psa_export_key()` and `psa_export_public_key()` in the application interface.
    * For an opaque driver, the wrapped key material (`const uint8_t *`), and its size in bytes (`size_t`). The driver builds the key material when the key is created and the core treats it opaquely.
    * For a remote driver, a key context (`const `*prefix*`_key_context_t *`).

* For functions that involve a multipart operation, the operation state type (`psa_XXX_operation_t`) is replaced by a driver-specific operation state type (*prefix*`_XXX_operation_t`).


## Transparent drivers

### Key format for transparent drivers

The format of a key for transparent drivers is the same as in applications. Refer to the documentation of `psa_export_key()` and `psa_export_public_key()`.

### Key management with transparent drivers

Transparent drivers do not provide key management functions, only cryptographic primitives.

There are API functions that combine key management with cryptographic calculations: `psa_generate_key()` and `psa_key_derivation_output_key()`. The corresponding driver functions pass an output buffer to the driver which is to contain the key in the export format. TODO: prototypes

### Fallback

If a transparent driver function is part of a capability which has a true `"fallback"` property and returns `PSA_ERROR_NOT_SUPPORTED`, the built-in software implementation will be called instead. Any other value (`PSA_SUCCESS` or a different error code) is returned to the application.

If there are multiple available transparent drivers, the core tries them in turn until one is declared without a true `"fallback"` property or returns a status other than `PSA_ERROR_NOT_SUPPORTED`.

If a transparent driver function is part of a capability where the `"fallback"` property is false or omitted, the core should not include any other code for this capability, whether built in or in another transparent driver.

## Opaque drivers

### Key format for opaque drivers

The format of a key for opaque drivers is a wrapped (encrypted) binary blob. The content of this blob is fully up to the driver. The core merely stores this blob.

### Key management with opaque drivers

To create a key with an opaque driver:

* The driver conveys the size of the wrapped key blob based on its attributes (type, size). TODO
* The core allocates memory for the wrapped key blob.
* The core calls the driver's import, generate or derive function.

To export a key from an opaque driver, the core calls the driver's export function, which takes the wrapped form of the key as input and writes the cleartext form as output. TODO: call it unwrap function rather than export? Or will this clash with wrapping as used in the API 1.x?

Copying a key from some location to an opaque location invokes the target location's import function. Copying a key from an opaque location to another location invokes the source location's export function. Copying a key within the same opaque location does not invoke driver code.

Destroying a key in an opaque location does not invoke driver code.

### Opaque driver persistent state

The core maintains persistent state on behalf of an opaque driver. The mechanism is the same as [for remote drivers](#remote-driver-persistent-state).

## Remote drivers

### Key format for remote drivers

With a remote driver, each key has a fixed-size key context of type *prefix*`_key_context_t`.

TODO: what about variable-size auxiliary data? For example a secure element that stores a private key, where the public key must be stored outside.

### Key management with remote drivers

Creating a key in a remote location happens in two steps.

1. The core calls the driver's key allocation function *prefix*`_allocate_key()`. This function typically allocates an identifier for the key without modifying the state of the secure element and stores the identifier in the key context.

2. The core calls the driver's key creation function (*prefix*`_import_key()`, *prefix*`_generate_key()`, *prefix*`_key_derivation_output_key()` or *prefix*`_copy_key()`).

If a failure occurs after the key allocation step but before the second step, the core will do one of the following:

* Fail the creation of the key without indicating this to the driver. This can happen, in particular, if the device loses power immediately after the key allocation function returns.
* Call the driver's key destruction function.

Destroying a key in a remote location calls the driver's key destruction function *prefix*`_destroy_key()`.

Copying a key from some location to an remote location invokes the target location's import function. Copying a key from an remote location to another location invokes the source location's export function. Copying a key within the same remote location does not invoke driver code.

### Remote driver persistent state

The core maintains persistent state on behalf of a remote driver. This persistent state consists of a single byte array whose size is indicated in the driver configuration. <!-- How? -->

TODO: how the state is passed to the driver; which driver functions can modify the state and how

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

## How to build Mbed TLS with drivers

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

## Mbed TLS internal architecture

TODO
