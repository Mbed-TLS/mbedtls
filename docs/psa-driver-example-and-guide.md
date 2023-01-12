# PSA Cryptoprocessor driver development examples

As of Mbed TLS 3.3.0, the PSA Driver Interface has only been partially implemented. As a result, the deliverables for writing a driver and the method for integrating a driver with Mbed TLS will vary depending on the operation being accelerated. This document describes how to write and integrate cryptoprocessor drivers depending on which operation or driver type is being implemented. 

The `docs/proposed/` directory contains three documents which pertain to the proposed, work-in-progress driver system. The [PSA Driver Interface](https://github.com/Mbed-TLS/mbedtls/blob/development/docs/proposed/psa-driver-interface.md) describes how drivers will interface with Mbed TLS in the future, as well as driver types, operation types, and entry points. As many key terms and concepts used in the examples in this document are defined in the PSA Driver Interface, it is recommended that developers read it prior to starting work on implementing drivers. 
The PSA Driver [Developer](https://github.com/Mbed-TLS/mbedtls/blob/development/docs/proposed/psa-driver-developer-guide.md) Guide describes the deliverables for writing a driver that can be used with Mbed TLS, and the PSA Driver [Integration](https://github.com/Mbed-TLS/mbedtls/blob/development/docs/proposed/psa-driver-integration-guide.md) Guide describes how a driver can be built alongside Mbed TLS.

## Background on how Mbed TLS calls drivers

The PSA Driver Interface specification specifies which cryptographic operations can be accelerated by third-party drivers. Operations that are completed within one step (one function call), such as verifying a signature, are called *Single-Part Operations*. On the other hand, operations that consist of multiple steps implemented by different functions called sequentially are called *Multi-Part Operations*. Single-part operations implemented by a driver will have one entry point, while multi-part operations will have multiple: one for each step.

There are two types of drivers: *transparent* or *opaque*. See below an excerpt from the PSA Driver Interface specification defining them:
* **Transparent** drivers implement cryptographic operations on keys that are provided in cleartext at the beginning of each operation. They are typically used for hardware **accelerators**. When a transparent driver is available for a particular combination of parameters (cryptographic algorithm, key type and size, etc.), it is used instead of the default software implementation. Transparent drivers can also be pure software implementations that are distributed as plug-ins to a PSA Cryptography implementation (for example, an alternative implementation with different performance characteristics, or a certified implementation).
* **Opaque** drivers implement cryptographic operations on keys that can only be used inside a protected environment such as a **secure element**, a hardware security module, a smartcard, a secure enclave, etc. An opaque driver is invoked for the specific [key location](https://github.com/Mbed-TLS/mbedtls/blob/development/docs/proposed/psa-driver-interface.md#lifetimes-and-locations) that the driver is registered for: the dispatch is based on the key's lifetime.

Mbed TLS contains a **driver dispatch layer** (also called a driver wrapper layer). For each cryptographic operation that supports driver acceleration (or sub-part of a multi-part operation), the library calls the corresponding function in the driver wrapper. Using flags set at compile time, the driver wrapper ascertains whether any present drivers support the operation. When no such driver is present, the built-in library implementation is called as a fallback (if allowed). When a compatible driver is present, the driver wrapper calls the driver entry point function provided by the driver author.

The long-term goal is for the driver dispatch layer to be auto-generated using a JSON driver description file provided by the driver author.
For some cryptographic operations, this auto-generation logic has already been implemented. When accelerating these operations, the instructions in the above documents can be followed. For the remaining operations which do not yet support auto-generation of the driver wrapper, developers will have to manually edit the driver dispatch layer and call their driver's entry point functions from there.

Auto-generation of the driver wrapper is supported for the operation entry points specified in the table below. Certain operations are only permitted for opaque drivers. All other operation entry points do not support auto-generation of the driver wrapper.

| Transparent Driver  | Opaque Driver       |
|---------------------|---------------------|
| `import_key`        | `import_key`        |
| `export_key`        | `export_key`        |
| `export_public_key` | `export_public_key` |
|                     | `copy_key`          |
|                     | `get_builtin_key`   |

### Process for Entry Points where auto-generation is implemented

If the driver is accelerating operations whose entry points are in the above table, the instructions in the driver [developer](https://github.com/Mbed-TLS/mbedtls/blob/development/docs/proposed/psa-driver-developer-guide.md) and [integration](https://github.com/Mbed-TLS/mbedtls/blob/development/docs/proposed/psa-driver-integration-guide.md) guides should be followed. 

**TODO: Provide brief summary of the method using the Mbed TLS test driver as an example**


### Process for Entry Points where auto-generation is not implemented

If the driver is accelerating operations whose entry points are not present in the table, a different process is followed where the developer manually edits the driver dispatch layer. In general, the following steps must be taken **for each single-part operation** or **for each sub-part of a multi-part operation**:

**1. Choose a driver prefix and a macro name that indicates whether the driver is enabled** \
A driver prefix is simply a word (often the name of the driver) that all functions/macros associated with the driver should begin with. This is similar to how most functions/macros in Mbed TLS begin with `PSA_XXX/psa_xx` or `MBEDTLS_XXX/mbedtls_xxx`. The macro name can follow the form `DRIVER_PREFIX_ENABLED` or something similar; it will be used to indicate the driver is available to be called. When building with the driver present, define this macro at compile time. For example, when using `make`, this is done using the `-D` flag. 

**2. Locate the function in the driver dispatch layer that corresponds to the entry point of the operation being accelerated.** \
The file `psa_crypto_driver_wrappers.c.jinja` contains the driver wrapper functions. For the entry points that have driver wrapper auto-generation implemented, the functions have been replaced with `jinja` templating logic. While the file has a `.jinja` extension, the driver wrapper functions for the remaining entry points are simple C functions. The names of these functions are of the form `psa_driver_wrapper` followed by the entry point name. So, for example, the function `psa_driver_wrapper_sign_hash()` corresponds to the `sign_hash` entry point.

**3. If a driver entry point function has been provided then ensure it has the same signature as the driver wrapper function.** \
If one has not been provided then write one. Its name should begin with the driver prefix, followed by transparent/opaque (depending on driver type), and end with the entry point name. It should have the same signature as the driver wrapper function. The purpose of the entry point function is to take arguments in PSA format for the implemented operation and return outputs/status codes in PSA format.

**4. Include the following in one of the driver header files:** 
```
#if defined(DRIVER_PREFIX_ENABLED)
#ifndef PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT
#define PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT
#endif
```

**5. Conditionally include header files required by the driver**
Include any header files required by the driver in `psa_crypto_driver_wrappers.h`, placing the `#include` statements within an `#if defined` block which checks if the driver is available:
```
#if defined(DRIVER_PREFIX_ENABLED)
#include ...
#endif
```

**6. Modify the driver wrapper function** \
Each driver wrapper function contains a `switch` statement which checks the location of the key. If the key is stored in local storage, then operations are performed by a transparent driver. If it is stored elsewhere, then operations are performed by an opaque driver.
 * **Transparent drivers:** Calls to drivers go under `case PSA_KEY_LOCATION_LOCAL_STORAGE`




<!-- the developer must manually edit the driver dispatch layer such that it first checks for the presence of the driver, and its compatibility with operation parameters (such as key type, algorithm type etc.). If the checks are passed, the driver's entry point function for that operation is called. The specification for the signature of entry point functions can be found [here](https://github.com/Mbed-TLS/mbedtls/blob/development/docs/proposed/psa-driver-interface.md#overview-of-driver-entry-points), but as a rule of thumb the signature for the driver entry point for an operation will be the same as the signature of its driver wrapper function. -->
