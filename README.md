README for Mbed TLS
===================

Mbed TLS is a C library that implements cryptographic primitives, X.509 certificate manipulation and the SSL/TLS and DTLS protocols. Its small code footprint makes it suitable for embedded systems.

Mbed TLS includes a reference implementation of the [PSA Cryptography API](#psa-cryptography-api). This is currently a preview for evaluation purposes only.

Configuration
-------------

Mbed TLS should build out of the box on most systems. Some platform specific options are available in the fully documented configuration file `include/mbedtls/config.h`, which is also the place where features can be selected. This file can be edited manually, or in a more programmatic way using the Python 3 script `scripts/config.py` (use `--help` for usage instructions).

Compiler options can be set using conventional environment variables such as `CC` and `CFLAGS` when using the Make and CMake build system (see below).

We provide some non-standard configurations focused on specific use cases in the `configs/` directory. You can read more about those in `configs/README.txt`

Documentation
-------------

The main Mbed TLS documentation is available via [ReadTheDocs](https://mbed-tls.readthedocs.io/).

Documentation for the PSA Cryptography API is available [on GitHub](https://arm-software.github.io/psa-api/crypto/).

To generate a local copy of the library documentation in HTML format, tailored to your compile-time configuration:

1. Make sure that [Doxygen](http://www.doxygen.nl/) is installed. We use version 1.8.11 but slightly older or more recent versions should work.
1. Run `make apidoc`.
1. Browse `apidoc/index.html` or `apidoc/modules.html`.

For other sources of documentation, see the [SUPPORT](SUPPORT.md) document.

Compiling
---------

There are currently three active build systems used within Mbed TLS releases:

-   GNU Make
-   CMake
-   Microsoft Visual Studio (Microsoft Visual Studio 2013 or later)

The main systems used for development are CMake and GNU Make. Those systems are always complete and up-to-date. The others should reflect all changes present in the CMake and Make build system, although features may not be ported there automatically.

The Make and CMake build systems create three libraries: libmbedcrypto, libmbedx509, and libmbedtls. Note that libmbedtls depends on libmbedx509 and libmbedcrypto, and libmbedx509 depends on libmbedcrypto. As a result, some linkers will expect flags to be in a specific order, for example the GNU linker wants `-lmbedtls -lmbedx509 -lmbedcrypto`.

### Tool versions

You need the following tools to build the library with the provided makefiles:

* GNU Make or a build tool that CMake supports.
* A C99 toolchain (compiler, linker, archiver). We actively test with GCC 5.4, Clang 3.8, IAR8 and Visual Studio 2013. More recent versions should work. Slightly older versions may work.
* Python 3.6 or later to generate the test code.
* Perl to run the tests.

### Make

We require GNU Make. To build the library and the sample programs, GNU Make and a C compiler are sufficient. Some of the more advanced build targets require some Unix/Linux tools.

We intentionally only use a minimum of functionality in the makefiles in order to keep them as simple and independent of different toolchains as possible, to allow users to more easily move between different platforms. Users who need more features are recommended to use CMake.

In order to build from the source code using GNU Make, just enter at the command line:

    make

In order to run the tests, enter:

    make check

The tests need Python to be built and Perl to be run. If you don't have one of them installed, you can skip building the tests with:

    make no_test

You'll still be able to run a much smaller set of tests with:

    programs/test/selftest

In order to build for a Windows platform, you should use `WINDOWS_BUILD=1` if the target is Windows but the build environment is Unix-like (for instance when cross-compiling, or compiling from an MSYS shell), and `WINDOWS=1` if the build environment is a Windows shell (for instance using mingw32-make) (in that case some targets will not be available).

Setting the variable `SHARED` in your environment will build shared libraries in addition to the static libraries. Setting `DEBUG` gives you a debug build. You can override `CFLAGS` and `LDFLAGS` by setting them in your environment or on the make command line; compiler warning options may be overridden separately using `WARNING_CFLAGS`. Some directory-specific options (for example, `-I` directives) are still preserved.

Please note that setting `CFLAGS` overrides its default value of `-O2` and setting `WARNING_CFLAGS` overrides its default value (starting with `-Wall -Wextra`), so if you just want to add some warning options to the default ones, you can do so by setting `CFLAGS=-O2 -Werror` for example. Setting `WARNING_CFLAGS` is useful when you want to get rid of its default content (for example because your compiler doesn't accept `-Wall` as an option). Directory-specific options cannot be overridden from the command line.

Depending on your platform, you might run into some issues. Please check the Makefiles in `library/`, `programs/` and `tests/` for options to manually add or remove for specific platforms. You can also check [the Mbed TLS Knowledge Base](https://mbed-tls.readthedocs.io/en/latest/kb/) for articles on your platform or issue.

In case you find that you need to do something else as well, please let us know what, so we can add it to the [Mbed TLS Knowledge Base](https://mbed-tls.readthedocs.io/en/latest/kb/).

### CMake

In order to build the source using CMake in a separate directory (recommended), just enter at the command line:

    mkdir /path/to/build_dir && cd /path/to/build_dir
    cmake /path/to/mbedtls_source
    cmake --build .

In order to run the tests, enter:

    ctest

The test suites need Python to be built and Perl to be executed. If you don't have one of these installed, you'll want to disable the test suites with:

    cmake -DENABLE_TESTING=Off /path/to/mbedtls_source

If you disabled the test suites, but kept the programs enabled, you can still run a much smaller set of tests with:

    programs/test/selftest

To configure CMake for building shared libraries, use:

    cmake -DUSE_SHARED_MBEDTLS_LIBRARY=On /path/to/mbedtls_source

There are many different build modes available within the CMake buildsystem. Most of them are available for gcc and clang, though some are compiler-specific:

-   `Release`. This generates the default code without any unnecessary information in the binary files.
-   `Debug`. This generates debug information and disables optimization of the code.
-   `Coverage`. This generates code coverage information in addition to debug information.
-   `ASan`. This instruments the code with AddressSanitizer to check for memory errors. (This includes LeakSanitizer, with recent version of gcc and clang.) (With recent version of clang, this mode also instruments the code with UndefinedSanitizer to check for undefined behaviour.)
-   `ASanDbg`. Same as ASan but slower, with debug information and better stack traces.
-   `MemSan`. This instruments the code with MemorySanitizer to check for uninitialised memory reads. Experimental, needs recent clang on Linux/x86\_64.
-   `MemSanDbg`. Same as MemSan but slower, with debug information, better stack traces and origin tracking.
-   `Check`. This activates the compiler warnings that depend on optimization and treats all warnings as errors.

Switching build modes in CMake is simple. For debug mode, enter at the command line:

    cmake -D CMAKE_BUILD_TYPE=Debug /path/to/mbedtls_source

To list other available CMake options, use:

    cmake -LH

Note that, with CMake, you can't adjust the compiler or its flags after the
initial invocation of cmake. This means that `CC=your_cc make` and `make
CC=your_cc` will *not* work (similarly with `CFLAGS` and other variables).
These variables need to be adjusted when invoking cmake for the first time,
for example:

    CC=your_cc cmake /path/to/mbedtls_source

If you already invoked cmake and want to change those settings, you need to
remove the build directory and create it again.

Note that it is possible to build in-place; this will however overwrite the
provided Makefiles (see `scripts/tmp_ignore_makefiles.sh` if you want to
prevent `git status` from showing them as modified). In order to do so, from
the Mbed TLS source directory, use:

    cmake .
    make

If you want to change `CC` or `CFLAGS` afterwards, you will need to remove the
CMake cache. This can be done with the following command using GNU find:

    find . -iname '*cmake*' -not -name CMakeLists.txt -exec rm -rf {} +

You can now make the desired change:

    CC=your_cc cmake .
    make

Regarding variables, also note that if you set CFLAGS when invoking cmake,
your value of CFLAGS doesn't override the content provided by cmake (depending
on the build mode as seen above), it's merely prepended to it.

#### Consuming Mbed TLS

Mbed TLS provides a package config file for consumption as a dependency in other
CMake projects. You can include Mbed TLS's CMake targets yourself with:

    find_package(MbedTLS)

If prompted, set `MbedTLS_DIR` to `${YOUR_MBEDTLS_INSTALL_DIR}/cmake`. This
creates the following targets:

- `MbedTLS::mbedcrypto` (Crypto library)
- `MbedTLS::mbedtls` (TLS library)
- `MbedTLS::mbedx509` (X509 library)

You can then use these directly through `target_link_libraries()`:

    add_executable(xyz)

    target_link_libraries(xyz
        PUBLIC MbedTLS::mbedtls
               MbedTLS::mbedcrypto
               MbedTLS::mbedx509)

This will link the Mbed TLS libraries to your library or application, and add
its include directories to your target (transitively, in the case of `PUBLIC` or
`INTERFACE` link libraries).

#### Mbed TLS as a subproject

Mbed TLS supports being built as a CMake subproject. One can
use `add_subdirectory()` from a parent CMake project to include Mbed TLS as a
subproject.

### Microsoft Visual Studio

The build files for Microsoft Visual Studio are generated for Visual Studio 2010.

The solution file `mbedTLS.sln` contains all the basic projects needed to build the library and all the programs. The files in tests are not generated and compiled, as these need Python and perl environments as well. However, the selftest program in `programs/test/` is still available.

Example programs
----------------

We've included example programs for a lot of different features and uses in [`programs/`](programs/README.md).
Please note that the goal of these sample programs is to demonstrate specific features of the library, and the code may need to be adapted to build a real-world application.

Tests
-----

Mbed TLS includes an elaborate test suite in `tests/` that initially requires Python to generate the tests files (e.g. `test\_suite\_mpi.c`). These files are generated from a `function file` (e.g. `suites/test\_suite\_mpi.function`) and a `data file` (e.g. `suites/test\_suite\_mpi.data`). The `function file` contains the test functions. The `data file` contains the test cases, specified as parameters that will be passed to the test function.

For machines with a Unix shell and OpenSSL (and optionally GnuTLS) installed, additional test scripts are available:

-   `tests/ssl-opt.sh` runs integration tests for various TLS options (renegotiation, resumption, etc.) and tests interoperability of these options with other implementations.
-   `tests/compat.sh` tests interoperability of every ciphersuite with other implementations.
-   `tests/scripts/test-ref-configs.pl` test builds in various reduced configurations.
-   `tests/scripts/depends.py` test builds in configurations with a single curve, key exchange, hash, cipher, or pkalg on.
-   `tests/scripts/all.sh` runs a combination of the above tests, plus some more, with various build options (such as ASan, full `config.h`, etc).

Instead of manually installing the required versions of all tools required for testing, it is possible to use the Docker images from our CI systems, as explained in [our testing infrastructure repository](https://github.com/Mbed-TLS/mbedtls-test/blob/main/README.md#quick-start).

Porting Mbed TLS
----------------

Mbed TLS can be ported to many different architectures, OS's and platforms. Before starting a port, you may find the following Knowledge Base articles useful:

-   [Porting Mbed TLS to a new environment or OS](https://mbed-tls.readthedocs.io/en/latest/kb/how-to/how-do-i-port-mbed-tls-to-a-new-environment-OS/)
-   [What external dependencies does Mbed TLS rely on?](https://mbed-tls.readthedocs.io/en/latest/kb/development/what-external-dependencies-does-mbedtls-rely-on/)
-   [How do I configure Mbed TLS](https://mbed-tls.readthedocs.io/en/latest/kb/compiling-and-building/how-do-i-configure-mbedtls/)

Mbed TLS is mostly written in portable C99; however, it has a few platform requirements that go beyond the standard, but are met by most modern architectures:

- Bytes must be 8 bits.
- All-bits-zero must be a valid representation of a null pointer.
- Signed integers must be represented using two's complement.
- `int` and `size_t` must be at least 32 bits wide.
- The types `uint8_t`, `uint16_t`, `uint32_t` and their signed equivalents must be available.

PSA cryptography API
--------------------

### PSA API

Arm's [Platform Security Architecture (PSA)](https://developer.arm.com/architectures/security-architectures/platform-security-architecture) is a holistic set of threat models, security analyses, hardware and firmware architecture specifications, and an open source firmware reference implementation. PSA provides a recipe, based on industry best practice, that allows security to be consistently designed in, at both a hardware and firmware level.

The [PSA cryptography API](https://arm-software.github.io/psa-api/crypto/) provides access to a set of cryptographic primitives. It has a dual purpose. First, it can be used in a PSA-compliant platform to build services, such as secure boot, secure storage and secure communication. Second, it can also be used independently of other PSA components on any platform.

The design goals of the PSA cryptography API include:

* The API distinguishes caller memory from internal memory, which allows the library to be implemented in an isolated space for additional security. Library calls can be implemented as direct function calls if isolation is not desired, and as remote procedure calls if isolation is desired.
* The structure of internal data is hidden to the application, which allows substituting alternative implementations at build time or run time, for example, in order to take advantage of hardware accelerators.
* All access to the keys happens through key identifiers, which allows support for external cryptoprocessors that is transparent to applications.
* The interface to algorithms is generic, favoring algorithm agility.
* The interface is designed to be easy to use and hard to accidentally misuse.

Arm welcomes feedback on the design of the API. If you think something could be improved, please open an issue on our Github repository. Alternatively, if you prefer to provide your feedback privately, please email us at [`mbed-crypto@arm.com`](mailto:mbed-crypto@arm.com). All feedback received by email is treated confidentially.

### PSA implementation in Mbed TLS

Mbed TLS includes a reference implementation of the PSA Cryptography API.
This implementation is not yet as mature as the rest of the library. Some parts of the code have not been reviewed as thoroughly, and some parts of the PSA implementation are not yet well optimized for code size.

The X.509 and TLS code can use PSA cryptography for a limited subset of operations. To enable this support, activate the compilation option `MBEDTLS_USE_PSA_CRYPTO` in `config.h`.

There are currently a few deviations where the library does not yet implement the latest version of the specification. Please refer to the [compliance issues on Github](https://github.com/Mbed-TLS/mbed-crypto/labels/compliance) for an up-to-date list.

### Upcoming features

Future releases of this library will include:

* A driver programming interface, which makes it possible to use hardware accelerators instead of the default software implementation for chosen algorithms.
* Support for external keys to be stored and manipulated exclusively in a separate cryptoprocessor.
* A configuration mechanism to compile only the algorithms you need for your application.
* A wider set of cryptographic algorithms.

License
-------

Unless specifically indicated otherwise in a file, Mbed TLS files are provided under a dual [Apache-2.0](https://spdx.org/licenses/Apache-2.0.html) OR [GPL-2.0-or-later](https://spdx.org/licenses/GPL-2.0-or-later.html) license. See the [LICENSE](LICENSE) file for the full text of these licenses, and [the 'License and Copyright' section in the contributing guidelines](CONTRIBUTING.md#License-and-Copyright) for more information.

Contributing
------------

We gratefully accept bug reports and contributions from the community. Please see the [contributing guidelines](CONTRIBUTING.md) for details on how to do this.

Contact
-------

* To report a security vulnerability in Mbed TLS, please email <mbed-tls-security@lists.trustedfirmware.org>. For more information, see [`SECURITY.md`](SECURITY.md).
* To report a bug or request a feature in Mbed TLS, please [file an issue on GitHub](https://github.com/Mbed-TLS/mbedtls/issues/new/choose).
* Please see [`SUPPORT.md`](SUPPORT.md) for other channels for discussion and support about Mbed TLS.
