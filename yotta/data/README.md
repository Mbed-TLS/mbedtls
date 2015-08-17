# mbed TLS

mbed TLS (formerly known as PolarSSL) makes it trivially easy for developers to include cryptographic and SSL/TLS capabilities in their (embedded) products, facilitating this functionality with a minimal coding footprint. It offers an SSL library with an intuitive API and readable source code.

The Beta release of mbed TLS is an integration of mbed TLS in mbed OS. It is a testing preview only and **not suitable for deployment**: there is currently no source of random numbers, meaning no security at all for (D)TLS communication and other protocols that rely on random numbers.

## Sample programs

This release includes the following examples:

1. [**TLS client:**](https://github.com/ARMmbed/mbedtls/blob/development/yotta/data/example-tls-client) found in `tests/example-tls-client`, downloads a file from an HTTPS server (mbed.org) and looks for a specific string in that file.

2. [**Self test:**](https://github.com/ARMmbed/mbedtls/blob/development/yotta/data/example-selftest) found in `tests/example-selftest`, tests different mbed TLS base functionalities.

3. [**Benchmark:**](https://github.com/ARMmbed/mbedtls/blob/development/yotta/data/example-benchmark) found in `tests/example-benchmark`, tests the time required to perform TLS base crypto functions.

These examples are integrated as yotta tests so that they are build automatically when you build mbed TLS. You'll find other examples in the various `tests/example-*` directories.

## Running TLS

Please follow the instructions in the [TLS client sample](https://github.com/ARMmbed/mbedtls/blob/development/yotta/data/example-tls-client). These include a list of prerequisites and an explanation of building mbed TLS with yotta.

## Configuring mbed TLS features

mbed TLS makes it easy to disable during the compilation any feature that is not needed for a particular project. The default configuration enables all modern and widely-used features, which should meet the need of any new project; it disables all features that are either older or less mainstrem, in order to keep the footprint low. The list of available compile flags is available in the fully documented [config.h file](https://github.com/ARMmbed/mbedtls/blob/development/include/mbedtls/config.h), present in the `mbedtls` directory of the yotta module.

Should you need to adjust those flags, you can provide your own configuration file with the suitable `#define` and `#undef` statements, to be included between the default definitions and the sanity checks. This file should be in your application's include directory and can be named freely; you just need to let mbed TLS know the name of the file, by using yotta's [configuration system](http://docs.yottabuild.org/reference/config.html). This name should go in your `config.json`, under mbedtls, as the key `user-config-file`, for example:

    {
       "mbedtls": {
          "user-config-file": "\"myapp/my_mbedtls_config_changes.h\""
       }
    }

Please note you need to provide the exact name that will be used in the `#include` directive, including the `<>` or quotes around the name.

## Contributing

We graciously accept bugs and contributions from the community. There are some requirements we need to fulfil in order to be able to integrate contributions in the main code:

* Simple bug fixes to existing code do not contain copyright themselves and we can integrate those without any issue. The same goes for trivial contributions.

* For larger contributions, e.g. a new feature, the code possibly falls under copyright law. We then need your consent to share in the ownership of the copyright. We have a form for that, which we will mail to you in case you submit a contribution or pull request that we deem this necessary for.

To contribute, please:

* [Check for open issues](https://github.com/ARMmbed/mbedtls/issues) or [start a discussion](https://tls.mbed.org/discussions) around a feature idea or a bug.

* Fork the [mbed TLS repository on Github](https://github.com/ARMmbed/mbedtls) to start making your changes.

* Write a test that shows that the bug was fixed or that the feature works as expected.

* Send a pull request and bug us until it gets merged and published. We will include your name in the ChangeLog :)
