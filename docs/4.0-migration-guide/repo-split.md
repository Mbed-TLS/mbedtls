## CMake as the only build system
Mbed TLS now uses CMake exclusively to configure and drive its build process.
Support for the GNU Make and Microsoft Visual Studio project-based build systems has been removed.

The previous `.sln` and `.vcxproj` files are no longer distributed or generated.

See the `Compiling` section in README.md for instructions on building the Mbed TLS libraries and tests with CMake.
If you develop in Microsoft Visual Studio, you could either generate a Visual Studio solution using a CMake generator, or open the CMake project directly in Visual Studio.

## Repository split
In Mbed TLS 4.0, the project was split into two repositories:
- [Mbed TLS](https://github.com/Mbed-TLS/mbedtls): provides TLS and X.509 functionality.
- [TF-PSA-Crypto](https://github.com/Mbed-TLS/TF-PSA-Crypto): provides the standalone cryptography library, implementing the PSA Cryptography API.
Mbed TLS consumes TF-PSA-Crypto as a submodule.
You should stay with Mbed TLS if you use TLS or X.509 functionality. You still have direct access to the cryptography library.

### File and directory relocations

The following table summarizes the file and directory relocations resulting from the repository split between Mbed TLS and TF-PSA-Crypto.
These changes reflect the move of cryptographic, cryptographic-adjacent, and platform components from Mbed TLS into the new TF-PSA-Crypto repository.

| Original location                       | New location(s)                                                                      | Notes |
|-----------------------------------------|--------------------------------------------------------------------------------------|-------|
| `library/*`  (\*)                       | `tf-psa-crypto/core/`<br>`tf-psa-crypto/drivers/builtin/src/`                        | Contains cryptographic, cryptographic-adjacent (e.g., ASN.1, Base64), and platform C modules and headers. |
| `include/mbedtls/*`  (\*)               | `tf-psa-crypto/include/mbedtls/`<br>`tf-psa-crypto/drivers/builtin/include/private/` | Public headers moved to `include/mbedtls`; now internal headers moved to `include/private`. |
| `include/psa`                           | `tf-psa-crypto/include/psa`                                                          | All PSA headers consolidated here. |
| `3rdparty/everest`<br>`3rdparty/p256-m` | `tf-psa-crypto/drivers/everest`<br>`tf-psa-crypto/drivers/p256-m`                    | Third-party crypto driver implementations. |

(\*) The `library` and `include/mbedtls` directories still exist in Mbed TLS, but not contain only TLS and X.509 components.

### Configuration file split
Cryptography and platform configuration options have been moved from `include/mbedtls/mbedtls_config.h` to `tf-psa-crypto/include/psa/crypto_config.h`, which is now mandatory.
See [Compile-time configuration](#compile-time-configuration).

The header `include/mbedtls/mbedtls_config.h` still exists and now contains only the TLS and X.509 configuration options.

If you use the Python script `scripts/config.py` to adjust your configuration, you do not need to modify your scripts to specify which configuration file to edit, the script automatically updates the correct file.

There has been significant changes in the configuration options, primarily affecting cryptography.

#### Cryptography configuration
- See [psa-transition.md](https://github.com/Mbed-TLS/TF-PSA-Crypto/blob/development/docs/psa-transition.md#compile-time-configuration).
- See also the following sections in the TF-PSA-Crypto 1.0 migration guide:
  - *PSA as the Only Cryptography API* and its sub-section *Impact on the Library Configuration*
  - *Random Number Generation Configuration*

#### TLS configuration
For details about TLS-related changes, see [Changes to TLS options](#changes-to-tls-options).

### Impact on some usages of the library

#### Checking out a branch or a tag
After checking out a branch or tag of the Mbed TLS repository, you must now recursively update the submodules, as TF-PSA-Crypto contains itself a nested submodule:
```
git submodule update --init --recursive
```

#### Linking directly to a built library
The Mbed TLS CMake build system still provides the cryptography libraries under their legacy name, `libmbedcrypto.<ext>`, so you can continue linking against them.
The cryptography libraries are also now provided as `libtfpsacrypto.<ext>` like in the TF-PSA-Crypto repository.

#### Linking through a CMake target of the cryptography library
The base name of the CMake cryptography library target has been changed from `mbedcrypto` to `tfpsacrypto`.
If no target prefix is specified through the MBEDTLS_TARGET_PREFIX option, the associated CMake target is thus now `tfpsacrypto`.

The same renaming applies to the cryptography library targets declared as part of the Mbed TLS CMake package.
When no global target prefix is defined, use `MbedTLS::tfpsacrypto` instead of `MbedTLS::mbedcrypto`.

As an example, the following CMake code:
```
find_package(MbedTLS REQUIRED)
target_link_libraries(myapp PRIVATE MbedTLS::mbedtls MbedTLS::mbedx509 MbedTLS::mbedcrypto)

```
would be updated to something like
```
find_package(MbedTLS REQUIRED)
target_link_libraries(myapp PRIVATE MbedTLS::mbedtls MbedTLS::mbedx509 MbedTLS::tfpsacrypto)
```

For more information, see the CMake section of `README.md`.
You can also refer to the following example programs demonstrating how to consume Mbed TLS via CMake:
* `programs/test/cmake_subproject`
* `programs/test/cmake_package`
* `programs/test/cmake_package_install`.

#### Using Mbed TLS Crypto pkg-config file
The Mbed TLS CMake build system still provides the pkg-config file mbedcrypto.pc, so you can continue using it. Internally, it now references the `tfpsacrypto` library.
A new pkg-config file, `tfpsacrypto.pc`, is also provided.
Both `mbedcrypto.pc` and `tfpsacrypto.pc` are functionally equivalent, providing the same compiler and linker flags.

### Audience-Specific Notes

#### Application Developers using a distribution package
- See [Impact on usages of the library](#impact-on-some-usages-of-the-library) for the possible impacts on:
  - Linking against the cryptography library or CMake targets.
  - Use the updated `pkg-config` files (`mbedcrypto.pc` / `tfpsacrypto.pc`).

### Developer or package maintainers
If you build or distribute Mbed TLS:
- The build system is now CMake only, Makefiles and Visual Studio projects are removed.
- You may need to adapt packaging scripts to handle the TF-PSA-Crypto submodule.
- You should update submodules recursively after checkout.
- Review [File and directory relocations](#file-and-directory-relocations) for updated paths.
- See [Impact on usages of the library](#impact-on-some-usages-of-the-library) for the possible impacts on:
  - Linking against the cryptography library or CMake targets.
  - Use the updated `pkg-config` files (`mbedcrypto.pc` / `tfpsacrypto.pc`).
- Configuration note: cryptography and platform options are now in `crypto_config.h` (see [Configuration file split](#configuration-file-split)).

### Platform Integrators
If you integrate Mbed TLS with a platform or hardware drivers:
- TF-PSA-Crypto is now a submodule, update integration scripts to initialize submodules recursively.
- The PSA driver wrapper is now generated in TF-PSA-Crypto.
- Platform-specific configuration are now handled in `crypto_config.h`.
- See [Repository split](#repository-split) for how platform components moved to TF-PSA-Crypto.
