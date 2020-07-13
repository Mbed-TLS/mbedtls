PSA Cryptoprocessor Driver Interface
====================================

This document describes an interface for cryptoprocessor drivers in the PSA cryptography API. This interface complements the PSA Cryptography API specification, which describes the interface between a PSA Cryptography implementation and an application.

This specification is work in progress and should be considered to be in a beta stage. There is ongoing work to implement this interface in Mbed TLS, which is the reference implementation of the PSA Cryptography API. At this stage, Arm does not expect major changes, but minor changes are expected based on experience from the first implementation and on external feedback.

Time-stamp: "2020/07/13 10:03:05 GMT"

## Introduction

### Purpose of the driver interface

The PSA Cryptography API defines an interface that allows applications to perform cryptographic operations in a uniform way regardless of how the operations are performed. Under the hood, different keys may be processed in different hardware or in different logical partitions, and different algorithms may involve different hardware or software components.

The driver interface allows implementations of the PSA Crypytography API to be built compositionally. An implementation of the PSA Cryptography API is composed of a **core** and zero or more **drivers**. The core handles key management, enforces key usage policies, and dispatches cryptographic operations either to the applicable driver or to built-in code.

Functions in the PSA Cryptography API invoke functions in the core. Code from the core calls drivers as described in the present document.

### Types of drivers

The PSA Cryptography driver interface supports two types of cryptoprocessors, and accordingly two types of drivers.

* **Transparent** drivers implement cryptographic operations on keys that are provided in cleartext at the beginning of each operation. They are typically used for hardware **accelerators**. When a transparent driver is available for a particular combination of parameters (cryptographic algorithm, key type and size, etc.), it is used instead of the default software implementation. Transparent drivers can also be pure software implementations that are distributed as plug-ins to a PSA Crypto implementation.
* **Opaque** drivers implement cryptographic operations on keys that can only be used inside a protected environment such as a **secure element**, a hardware security module, a smartcard, a secure enclave, etc. An opaque driver is invoked for the specific key location that the driver is registered for: the dispatch is based on the key's lifetime.

### Requirements

The present specification was designed to fulfil the following high-level requirements.

[Req.plugins] It is possible to combine multiple drivers from different providers into the same implementation, without any prior arrangement other than choosing certain names and values from disjoint namespaces.

[Req.compile] It is possible to compile the code of each driver and of the core separately, and link them together. A small amount of glue code may need to be compiled once the list of drivers is available.

[Req.types] Support drivers for the following types of hardware: accelerators that operate on keys in cleartext; cryptoprocessors that can wrap keys with a built-in keys but not store user keys; and cryptoprocessors that store key material.

[Req.portable] The interface between drivers and the core does not involve any platform-specific consideration. Driver calls are simple C functions. Interactions between driver code and hardware happen inside the driver (and in fact a driver need not involve any hardware at all).

[Req.location] Applications can tell which location values correspond to which secure element drivers.

[Req.fallback] Accelerator drivers can specify that they do not fully support a cryptographic mechanism and that a fallback to core code may be necessary. Conversely, if an accelerator fully supports cryptographic mechanism, the core does not need to include code for this mechanism.

[Req.mechanisms] Drivers can specify which mechanisms they support. A driver's code will not be invoked for cryptographic mechanisms that it does not support.

## Overview of drivers

### Deliverables for a driver

To write a driver, you need to implement some functions with C linkage, and to declare these functions in a **driver description file**. The driver description file declares which functions the driver implements and what cryptographic mechanisms they support. Depending on the driver type, you may also need to define some C types and macros in a header file.

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
* `"type"` (mandatory, string). One of `"transparent"` or `"opaque"`.
* `"headers"` (optional, array of strings). A list of header files. These header files must define the types provided by the driver and may declare the functions provided by the driver. They may include other PSA headers and standard headers of the platform. Whether they may include other headers is implementation-specific. If omitted, the list of headers is empty.
* `"capabilities"` (mandatory, array of [capabilities](#driver-description-capability)).
A list of **capabilities**. Each capability describes a family of functions that the driver implements for a certain class of cryptographic mechanisms.
* `"key_context"` (not permitted for transparent drivers, mandatory for opaque drivers): information about the [representation of keys](#key-format-for-opaque-drivers).
* `"persistent_state_size"` (not permitted for transparent drivers, optional for opaque drivers, integer or string). The size in bytes of the [persistent state of the driver](#opaque-driver-persistent-state). This may be either a non-negative integer or a C constant expression of type `size_t`.
* `"location"` (not permitted for transparent drivers, optional for opaque drivers, integer or string). The location value for which this driver is invoked. This may be either a non-negative integer or a C constant expression of type `psa_key_location_t`.

#### Driver description capability

A capability declares a family of functions that the driver implements for a certain class of cryptographic mechanisms. The capability specifies which key types and algorithms are covered and the names of the types and functions that implement it.

A capability is a JSON object containing the following properties:

* `"functions"` (optional, list of strings). Each element is the name of a [driver function](#driver-functions) or driver function family. If specified, the core will invoke this capability of the driver only when performing one of the specified operations. If omitted, the `"algorithms"` property is mandatory and the core will invoke this capability of the driver for all operations that are applicable to the specified algorithms. The driver must implement all the specified or implied functions, as well as the types if applicable.
* `"algorithms"` (optional, list of strings). Each element is an [algorithm specification](#algorithm-specifications). If specified, the core will invoke this capability of the driver only when performing one of the specified algorithms. If omitted, the core will invoke this capability for all applicable algorithms.
* `"key_types"` (optional, list of strings). Each element is a [key type specification](#key-type-specifications). If specified, the core will invoke this capability of the driver only for operations involving a key with one of the specified key types. If omitted, the core will invoke this capability of the driver for all applicable key types.
* `"key_sizes"` (optional, list of integers). If specified, the core will invoke this capability of the driver only for operations involving a key with one of the specified key sizes. If omitted, the core will invoke this capability of the driver for all applicable key sizes. Key sizes are expressed in bits.
* `"names"` (optional, object). A mapping from function names described by the `"functions"` property, to the name of the C function in the driver that implements the corresponding function. If a function is not listed here, name of the driver function that implements it is the driver's prefix followed by an underscore (`_`) followed by the function name. If this property is omitted, it is equivalent to an empty object (so each function *suffix* is implemented by a function with called *prefix*`_`*suffix*).
* `"fallback"` (optional for transparent drivers, not permitted for opaque drivers, boolean). If present and true, the driver may return `PSA_ERROR_NOT_SUPPORTED`, in which case the core should call another driver or use built-in code to perform this operation. If absent or false, the core should not include built-in code to perform this particular cryptographic mechanism.

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

### Algorithm and key specifications

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

### Driver functions

#### Overview of driver functions

Drivers define functions, each of which implements an aspect of a capability of a driver, such as a cryptographic operation, a part of a cryptographic operation, or a key management action. Most driver functions correspond to a particular function in the PSA Cryptography API. For example, if a call to `psa_sign_hash()` is dispatched to a driver, it invokes the driver's `sign_hash` function.

All driver functions return a status of type `psa_status_t` which should use the status codes documented for PSA services in general and for PSA Crypto in particular: `PSA_SUCCESS` indicates that the function succeeded, and `PSA_ERROR_xxx` values indicate that an error occurred.

The signature of a driver function generally looks like the signature of the PSA Crypto API that it implements, with some modifications. This section gives an overview of modifications that apply to whole classes of functions. Refer to the reference section for each function or function family for details.

* For functions that operate on an existing key, the `psa_key_id_t` parameter is replaced by a sequence of three parameters that describe the key:
    1. `const psa_key_attributes_t *attributes`: the key attributes.
    2. `const uint8_t *key_buffer`: a key material or key context buffer.
    3. `size_t key_buffer_size`: the size of the key buffer in bytes.

    For transparent drivers, the key buffer contains the key material, in the same format as defined for `psa_export_key()` and `psa_export_public_key()` in the PSA Cryptography API. For opaque drivers, the content of the key buffer is entirely up to the driver.

* For functions that involve a multi-part operation, the operation state type (`psa_XXX_operation_t`) is replaced by a driver-specific operation state type (*prefix*`_XXX_operation_t`).

Some functions are grouped in families that must be implemented as a whole. If a driver supports a function family, it must provide all the functions in the family.

#### General considerations on driver function parameters

Buffer parameters for driver functions obey the following conventions:

* An input buffer has the type `const uint8_t *` and is immediately followed by a parameter of type `size_t` that indicates the buffer size.
* An output buffer has the type `uint8_t *` and is immediately followed by a parameter of type `size_t` that indicates the buffer size. A third parameter of type `size_t *` is provided to report the actual buffer size if the function succeeds.
* An in-out buffer has the type `uint8_t *` and is immediately followed by a parameter of type `size_t` that indicates the buffer size. Note that the buffer size does not change.

Buffers of size 0 may be represented with either a null pointer or a non-null pointer.

Input buffers and other input-only parameters (`const` pointers) may be in read-only memory. Overlap is possible between input buffers, and between an input buffer and an output buffer, but not between two output buffers or between a non-buffer parameter and another parameter.

#### Driver functions for single-part cryptographic operations

The following driver functions perform a cryptographic operation in one shot (single-part operation):

* `"hash_compute"` (transparent drivers only): calculation of a hash. Called by `psa_hash_compute()` and `psa_hash_compare()`. To verify a hash with `psa_hash_compare()`, the core calls the driver's `"hash_compute"` function and compares the result with the reference hash value.
* `"mac_compute"`: calculation of a MAC. Called by `psa_mac_compute()` and possibly `psa_mac_verify()`. To verify a mac with `psa_mac_verify()`, the core calls an applicable driver's `"mac_verify"` function if there is one, otherwise the core calls an applicable driver's `"mac_compute"` function and compares the result with the reference MAC value.
* `"mac_verify"`: verification of a MAC. Called by `psa_mac_verify()`. This function is mainly useful for drivers of secure elements that verify a MAC without revealing the correct MAC. Although transparent drivers may implement this function in addition to `"mac_compute"`, it is generally not useful because the core can call the `"mac_compute"` function and compare with the expected MAC value.
* `"cipher_encrypt"`: unauthenticated symmetric cipher encryption. Called by `psa_cipher_encrypt()`.
* `"cipher_decrypt"`: unauthenticated symmetric cipher decryption. Called by `psa_cipher_decrypt()`.
* `"aead_encrypt"`: authenticated encryption with associated data. Called by `psa_aead_encrypt()`.
* `"aead_decrypt"`: authenticated decryption with associated data. Called by `psa_aead_decrypt()`.
* `"asymmetric_encrypt"`: asymmetric encryption. Called by `psa_asymmetric_encrypt()`.
* `"asymmetric_decrypt"`: asymmetric decryption. Called by `psa_asymmetric_decrypt()`.
* `"sign_hash"`: signature of an already calculated hash. Called by `psa_sign_hash()` and possibly `psa_sign_message()`. To sign a message with `psa_sign_message()`, the core calls an applicable driver's `"sign_message"` function if there is one, otherwise the core calls an applicable driver's `"hash_compute"` function followed by an applicable driver's `"sign_hash"` function.
* `"verify_hash"`: verification of an already calculated hash. Called by `psa_verify_hash()` and possibly `psa_verify_message()`. To verify a message with `psa_verify_message()`, the core calls an applicable driver's `"verify_message"` function if there is one, otherwise the core calls an applicable driver's `"hash_compute"` function followed by an applicable driver's `"verify_hash"` function.
* `"sign_message"`: signature of a message. Called by `psa_sign_message()`.
* `"verify_message"`: verification of a message. Called by `psa_verify_message()`.
* `"key_agreement"`: key agreement without a subsequent key derivation. Called by `psa_raw_key_agreement()` and possibly `psa_key_derivation_key_agreement()`.

### Driver functions for multi-part operations

#### General considerations on multi-part operations

The functions that implement each step of a multi-part operation are grouped into a family. A driver that implements a multi-part operation must define all of the functions in this family as well as a type that represents the operation context. The lifecycle of a driver operation context is similar to the lifecycle of an API operation context:

1. The core initializes operation context objects to either all-bits-zero or to logical zero (`{0}`), at its discretion.
1. The core calls the `xxx_setup` function for this operation family. If this fails, the core destroys the operation context object without calling any other driver function on it.
1. The core calls other functions that manipulate the operation context object, respecting the constraints.
1. If any function fails, the core calls the driver's `xxx_abort` function for this operation family, then destroys the operation context object without calling any other driver function on it.
1. If a “finish” function fails, the core destroys the operation context object without calling any other driver function on it. The finish functions are: *prefix*`_mac_sign_finish`, *prefix*`_mac_verify_finish`, *prefix*`_cipher_fnish`, *prefix*`_aead_finish`, *prefix*`_aead_verify`.

If a driver implements a multi-part operation but not the corresponding single-part operation, the core calls the driver's multipart operation functions to perform the single-part operation.

#### Multi-part operation function family `"hash_multipart"`

This family corresponds to the calculation of a hash in one multiple parts.

This family applies to transparent drivers only.

This family requires the following type and functions:

* Type `"hash_operation_t"`: the type of a hash operation context. It must be possible to copy a hash operation context byte by byte, therefore hash operation contexts must not contain any embedded pointers (except pointers to global data that do not change after the setup step).
* `"hash_setup"`: called by `psa_hash_setup()`.
* `"hash_update"`: called by `psa_hash_update()`.
* `"hash_finish"`: called by `psa_hash_finish()` and `psa_hash_verify()`.
* `"hash_abort"`: called by all multi-part hash functions.

To verify a hash with `psa_hash_verify()`, the core calls the driver's *prefix`_hash_finish` function and compares the result with the reference hsah value.

For example, a driver with the prefix `"acme"` that implements the `"hash_multipart"` function family must define the following type and functions (assuming that the capability does not use the `"names"` property to declare different type and function names):

```
typedef ... acme_hash_operation_t;
psa_status_t acme_hash_setup(acme_hash_operation_t *operation,
                             psa_algorithm_t alg);
psa_status_t acme_hash_update(acme_hash_operation_t *operation,
                              const uint8_t *input,
                              size_t input_length);
psa_status_t acme_hash_finish(acme_hash_operation_t *operation,
                              uint8_t *hash,
                              size_t hash_size,
                              size_t *hash_length);
psa_status_t acme_hash_abort(acme_hash_operation_t *operation);
```

#### Operation family `"mac_multipart"`

TODO

#### Operation family `"mac_verify_multipart"`

TODO

#### Operation family `"cipher_encrypt_multipart"`

TODO

#### Operation family `"cipher_decrypt_multipart"`

TODO

#### Operation family `"aead_encrypt_multipart"`

TODO

#### Operation family `"aead_decrypt_multipart"`

TODO

#### Operation family `"key_derivation"`

This family requires the following type and functions:

* Type `"key_derivation_operation_t"`: the type of a key derivation operation context.
* `"key_derivation_setup"`: called by `psa_key_derivation_setup()`.
* `"key_derivation_set_capacity"`: called by `psa_key_derivation_set_capacity()`. The core will always enforce the capacity, therefore this function does not need to do anything for algorithms where the output stream only depends on the effective generated length and not on the capacity.
* `"key_derivation_input_bytes"`: called by `psa_key_derivation_input_bytes()` and `psa_key_derivation_input_key()`. For transparent drivers, when processing a call to `psa_key_derivation_input_key()`, the core always calls the applicable driver's `"key_derivation_input_bytes"` function.
* `"key_derivation_input_key"` (opaque drivers only)
* `"key_derivation_output_bytes"`: called by `psa_key_derivation_output_bytes()`; also by `psa_key_derivation_output_key()` for transparent drivers.
* `"key_derivation_abort"`: called by all key derivation functions.

TODO: key input and output for opaque drivers; deterministic key generation for transparent drivers

TODO

### Driver functions for key management

The driver functions for key management differs significantly between [transparent drivers](#key-management-with-transparent-drivers) and [opaque drivers](#key-management-with-transparent-drivers). Refer to the applicable section for each driver type.

### Miscellaneous driver functions

#### Driver initialization

An opaque driver may declare an `"init"` function in a capability with no algorithm, key type or key size. If so, the driver calls this function once during the initialization of the PSA Crypto subsystem. If the init function of any driver fails, the initialization of the PSA Crypto subsystem fails.

When multiple drivers have an init function, the order in which they are called is unspecified. It is also unspecified whether other drivers' init functions are called if one or more init function fails.

On platforms where the PSA Crypto implementation is a subsystem of a single application, the initialization of the PSA Crypto subsystem takes place during the call to `psa_crypto_init()`. On platforms where the PSA Crypto implementation is separate from the application or applications, the initialization the initialization of the PSA Crypto subsystem takes place before or during the first time an application calls `psa_crypto_init()`.

For transparent drivers, the init function does not take any parameter.

For opaque drivers, the init function takes the following parameters:

* `uint8_t *persistent_state`: the driver's persistent state. On the first boot of the device, this contains all-bits-zero. On subsequent boots, the core loads the last saved state.
* `size_t persistent_state_size`: the size of the persistent state in bytes.

For an opaque driver, if the init function succeeds, the core saves the updated persistent state. If the init function fails, the persistent state is unchanged.

### Combining multiple drivers

To declare a cryproprocessor can handle both cleartext and plaintext keys, you need to provide two driver descriptions, one for a transparent driver and one for an opaque driver. You can use the mapping in capabilities' `"names"` property to arrange for driver functions to map to the same C function.

## Transparent drivers

### Key format for transparent drivers

The format of a key for transparent drivers is the same as in applications. Refer to the documentation of `psa_export_key()` and `psa_export_public_key()`.

### Key management with transparent drivers

Transparent drivers may provide the following key management functions:

* `"generate_key"`: called by `psa_generate_key()`, only when generating a key pair (key such that `PSA_KEY_TYPE_IS_ASYMMETRIC` is true).
* `"derive_key"`: called by `psa_key_derivation_output_key()`, only when deriving a key pair (key such that `PSA_KEY_TYPE_IS_ASYMMETRIC` is true).
* `"export_public_key"`: called by the core to obtain the public key of a key pair. The core may call this function at any time to obtain the public key, which can be for `psa_export_public_key()` but also at other times, including during a cryptographic operation that requires the public key such as a call to `psa_verify_message()` on a key pair object.

Transparent drivers are not involved when importing, exporting, copying or destroying keys, or when generating or deriving symmetric keys.

### Fallback

If a transparent driver function is part of a capability which has a true `"fallback"` property and returns `PSA_ERROR_NOT_SUPPORTED`, the built-in software implementation will be called instead. Any other value (`PSA_SUCCESS` or a different error code) is returned to the application.

If there are multiple available transparent drivers, the core tries them in turn until one is declared without a true `"fallback"` property or returns a status other than `PSA_ERROR_NOT_SUPPORTED`.

If a transparent driver function is part of a capability where the `"fallback"` property is false or omitted, the core should not include any other code for this capability, whether built in or in another transparent driver.

## Opaque drivers

Opaque drivers allow a PSA Cryptography implementation to delegate cryptographic operations to a separate environment that might not allow exporting key material in cleartext. The opaque driver interface is designed so that the core never inspects the representation of a key. The opaque driver interface is designed to support two subtypes of cryptoprocessors:

* Some cryptoprocessors do not have persistent storage for individual keys. The representation of a key is the key material wrapped with a master key which is located in the cryptoprocessor and never exported from it. The core stores this wrapped key material on behalf of the cryptoprocessor.
* Some cryptoprocessors have persistent storage for individual keys. The representation of a key is an identifier such as label or slot number. The core stores this identifier.

### Key format for opaque drivers

The format of a key for opaque drivers is an opaque blob. The content of this blob is fully up to the driver. The core merely stores this blob.

Note that since the core stores the key context blob as it is in memory, it must only contain data that is meaningful after a reboot. In particular, it must not contain any pointers or transient handles.

The `"key_context"` property in the [driver description](#driver-description-top-level-element) specifies how to calculate the size of the key context as a function of the key type and size. This is an object with the following properties:

* `"base_size"` (integer or string, optional): this many bytes are included in every key context. If omitted, this value defaults to 0.
* `"key_pair_size"` (integer or string, optional): this many bytes are included in every key context for a key pair. If omitted, this value defaults to 0.
* `"public_key_size"` (integer or string, optional): this many bytes are included in every key context for a public key. If omitted, this value defaults to 0.
* `"symmetric_factor"` (integer or string, optional): every key context for a symmetric key includes this many times the key size. If omitted, this value defaults to 0.
* `"store_public_key"` (boolean, optional): If specified and true, for a key pair, the key context includes space for the public key. If omitted or false, no additional space is added for the public key.
* `"size_function"` (string, optional): the name of a function that returns the number of bytes that the driver needs in a key context for a key. This may be a pointer to function. This must be a C identifier; more complex expressions are not permitted. If the core uses this function, it supersedes all the other properties.

The integer properties must be C language constants. A typical value for `"base_size"` is `sizeof(acme_key_context_t)` where `acme_key_context_t` is a type defined in a driver header file.

#### Size of a dynamically allocated key context

If the core supports dynamic allocation for the key context and chooses to use it, and the driver specification includes the `"size_function"` property, the size of the key context is at least
```
size_function(key_type, key_bits)
```
where `size_function` is the function named in the `"size_function"` property, `key_type` is the key type and `key_bits` is the key size in bits. The prototype of the size function is
```
size_t size_function(psa_key_type_t key_type, size_t key_bits);
```

#### Size of a statically allocated key context

If the core does not support dynamic allocation for the key context or chooses not to use it, or if the driver specification does not include the `"size_function"` property, the size of the key context for a key of type `key_type` and of size `key_bits` bits is:

* For a key pair (`PSA_KEY_TYPE_IS_KEY_PAIR(key_type)` is true):
    ```
    base_size + key_pair_size + public_key_overhead
    ```
    where `public_key_overhead = PSA_EXPORT_PUBLIC_KEY_MAX_SIZE(key_type, key_bits)` if the `"store_public_key"` property is true and `public_key_overhead = 0` otherwise.

* For a public key (`PSA_KEY_TYPE_IS_PUBLIC_KEY(key_type)` is true):
    ```
    base_size + public_key_size
    ```

* For a symmetric key (not a key pair or public key):
    ```
    base_size + symmetric_factor * key_bytes
    ```
    where `key_bytes = ((key_bits + 7) / 8)` is the key size in bytes.

#### Key context size for a secure element with storage

If the key is stored in the secure element and the driver only needs to store a label for the key, use `"base_size"` as the size of the label plus any other metadata that the driver needs to store, and omit the other properties.

If the key is stored in the secure element, but the secure element does not store the public part of a key pair and cannot recompute it on demand, additionally use the `"store_public_key"` property with the value `true`. Note that this only influences the size of the key context: the driver code must copy the public key to the key context and retrieve it on demand in its `export_public_key` function.

#### Key context size for a secure element without storage

If the key is stored in wrapped form outside the secure element, and the wrapped form of the key plus any metadata has up to *N* bytes of overhead, use *N* as the value of the `"base_size"` property and set the `"symmetric_factor"` property to 1. Set the `"key_pair_size"` and `"public_key_size"` properties appropriately for the largest supported key pair and the largest supported public key respectively.

### Key management with opaque drivers

Transparent drivers may provide the following key management functions:

* `"allocate_key"`: called by `psa_import_key()`, `psa_generate_key()`, `psa_key_derivation_output_key()` or `psa_copy_key()` before creating a key in the location of this driver.
* `"import_key"`: called by `psa_import_key()`, or by `psa_copy_key()` when copying a key from another location.
* `"export_key"`: called by `psa_export_key()`, or by `psa_copy_key()` when copying a key from to location.
* `"export_public_key"`: called by the core to obtain the public key of a key pair. The core may call this function at any time to obtain the public key, which can be for `psa_export_public_key()` but also at other times, including during a cryptographic operation that requires the public key such as a call to `psa_verify_message()` on a key pair object.
* `"copy_key"`: called by `psa_copy_key()` when copying a key within the same location.
* `"destroy_key"`: called by `psa_destroy_key()`.
* `"generate_key"`: called by `psa_generate_key()`.
* `"derive_key"`: called by `psa_key_derivation_output_key()`.

#### Key creation in a secure element without storage

This section describes the key creation process for secure elements that do not store the key material. The driver must obtain a wrapped form of the key material which the core will store. A driver for such a secure element has no `"allocate_key"` function.

When creating a key with an opaque driver which does not have an `"allocate_key"` function:

1. The core allocates memory for the key context.
2. The core calls the driver's import, generate, derive or copy function.
3. The core saves the resulting wrapped key material and any other data that the key context may contain.

#### Key creation in a secure element with storage

This section describes the key creation process for secure elements that have persistent storage for the key material. A driver for such a secure element has an `"allocate_key"` function whose intended purpose is to obtain an identifier for the key. This may be, for example, a unique label or a slot number.

When creating a persistent key with an opaque driver which does not have an `"allocate_key"` function:

1. The core calls the driver's `"allocate_key"` function. This function typically allocates an identifier for the key without modifying the state of the secure element and stores the identifier in the key context. This function should not modify the state of the secure element.

1. The core saves the key context to persistent storage.

1. The core saves the driver's persistent state.

1. The core calls the driver's key creation function.

If a failure occurs after the `"allocate_key"` step but before the call to the second driver function, the core will do one of the following:

* Fail the creation of the key without indicating this to the driver. This can happen, in particular, if the device loses power immediately after the key allocation function returns.
* Call the driver's `"destroy_key"` function.

TODO: explain the individual key management functions

### Opaque driver persistent state

The core maintains persistent state on behalf of an opaque driver. This persistent state consists of a single byte array whose size is given by the `"persistent_state_size"` property in the [driver description](#driver-description-top-level-element).

TODO: how the state is passed to the driver; which driver functions can modify the state and how; when the core saves the updated state

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
        PSA_KEY_PERSISTENCE_DEFAULT, PSA_KEY_LOCATION_acme));
psa_set_key_identifer(&attributes, 42);
psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
psa_set_key_size(&attributes, 128);
psa_set_key_algorithm(&attributes, PSA_ALG_GCM);
psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
psa_key_handle_t handle = 0;
psa_generate_key(&attributes, &handle);
```


## Using opaque drivers from an application

The  a compile-time constant for each opaque driver indicating its location called `PSA_KEY_LOCATION_`*prefix* where *prefix* is the value of the `"prefix"` property in the driver description. For convenience, Mbed TLS also declares a compile-time constant for the corresponding lifetime with the default persistence called `PSA_KEY_LIFETIME_`*prefix*. Therefore, to declare an opaque key in the location with the prefix `foo` with the default persistence, call `psa_set_key_lifetime` during the key creation as follows:
```
psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_foo);
```

To declare a volatile key:
```
psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(
        PSA_KEY_LOCATION_foo,
        PSA_KEY_PERSISTENCE_VOLATILE));
```

Generally speaking, to declare a key with a specified persistence:
```
psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(
        PSA_KEY_LOCATION_foo,
        persistence));
```

## Open questions

### Driver declarations

#### Declaring driver functions

The core may want to provide declarations for the driver functions so that it can compile code using them. At the time of writing this paragraph, the driver headers must define types but there is no obligation for them to declare functions. The core knows what the function names and argument types are, so it can generate prototypes.

It should be ok for driver functions to be function-like macros or function pointers.

#### Driver location values

How does a driver author decide which location values to use? It should be possible to combine drivers from different sources. Use the same vendor assignment as for PSA services?

Can the driver assembly process generate distinct location values as needed? This can be convenient, but it's also risky: if you upgrade a device, you need the location values to be the same between builds.

### Driver function interfaces

#### Driver function parameter conventions

Should 0-size buffers be guaranteed to have a non-null pointers?

Should drivers really have to cope with overlap?

Should the core guarantee that the output buffer size has the size indicated by the applicable buffer size macro (which may be an overestimation)?

### Partial computations in drivers

#### Substitution points

Earlier drafts of the driver interface had a concept of _substitution points_: places in the calculation where a driver may be called. Some hardware doesn't do the whole calculation, but only the “main” part. This goes both for transparent and opaque drivers. Some common examples:

* A processor that performs the RSA exponentiation, but not the padding. The driver should be able to leverage the padding code in the core.
* A processor that performs a block cipher operation only for a single block, or only in ECB mode, or only in CTR mode. The core would perform the block mode (CBC, CTR, CCM, ...).

This concept, or some other way to reuse portable code such as specifying inner functions like `psa_rsa_pad` in the core, should be added to the specification.

### Key management

#### Mixing drivers in key derivation

How does `psa_key_derivation_output_key` work when the extraction part and the expansion part use different drivers?

#### Public key not stored

ECC key pairs are stored as the private key value only. The public key needs to be calculated from that.

It's fairly common for secure elements to also store only the private value. When a key is generated randomly or derived, the hardware reports the public key, and it is up to the software to store it. The current design makes this the job of the driver. Should it be the work of the core instead?

Note that a solution also has to work for transparent keys, and when importing a private key into a secure element. If the core already has code to calculate the public key, it would make sense for the driver to be able to use it, especially in these cases.

### Opaque drivers

#### Opaque driver persistent state

Should the driver be able to update it at any time?

<!--
Local Variables:
time-stamp-line-limit: 40
time-stamp-start: "Time-stamp: *\""
time-stamp-end: "\""
time-stamp-format: "%04Y/%02m/%02d %02H:%02M:%02S %Z"
time-stamp-time-zone: "GMT"
End:
-->
