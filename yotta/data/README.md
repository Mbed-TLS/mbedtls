# mbed TLS

mbed TLS (formerly known as PolarSSL) makes it trivially easy for developers to include cryptographic and SSL/TLS capabilities in their embedded products, with a minimal code footprint. It offers an SSL library with an intuitive API and readable source code.

The Beta release of mbed TLS integrates the mbed TLS library into mbed OS, mbed SDK and yotta. This is a preview release intended for evaluation only and is **not recommended for deployment**. This implementation currently implements no secure source of random numbers, weakening it's security.

## Sample programs

This release includes the following examples:

1. [**TLS client:**](https://github.com/ARMmbed/mbedtls/blob/development/yotta/data/example-tls-client) found in `test/example-tls-client`, downloads a test file from an HTTPS server and looks for a specific string in that file.

2. [**Self test:**](https://github.com/ARMmbed/mbedtls/blob/development/yotta/data/example-selftest) found in `test/example-selftest`, tests different basic functions in the mbed TLS library.

3. [**Benchmark:**](https://github.com/ARMmbed/mbedtls/blob/development/yotta/data/example-benchmark) found in `test/example-benchmark`, measures the time taken to perform basic cryptographic functions used in the library.

These examples are integrated as yotta tests so that they are built automatically when you build mbed TLS. You'll find other examples in the various `test/example-*` directories alongside these examples.

## Running TLS

Please follow the instructions in the [TLS client sample](https://github.com/ARMmbed/mbedtls/blob/development/yotta/data/example-tls-client) directory, to build and run the example. These include a list of prerequisites and an explanation of building mbed TLS with yotta.

## Configuring mbed TLS features

mbed TLS makes it easy to disable any feature during compilation that isn't required for a particular project. The default configuration enables all modern and widely-used features which should meet the needs of new projects and disables all features that are older or less common, to minimise the code footprint. The list of available compilation flags is available in the fully documented [config.h file](https://github.com/ARMmbed/mbedtls/blob/development/include/mbedtls/config.h), present in the `mbedtls` directory of the yotta module.

Should you need to adjust those flags, you can provide your own configuration file with suitable `#define` and `#undef` statements, to be included between the default definitions and the sanity checks. This file should be in your application's include directory and can be named freely; you just need to let mbed TLS know the name of the file, by using yotta's [configuration system](http://docs.yottabuild.org/reference/config.html). This name should go in your `config.json`, under mbedtls, as the key `user-config-file`, for example:

    {
       "mbedtls": {
          "user-config-file": "\"myapp/my_mbedtls_config_changes.h\""
       }
    }

Please note you need to provide the exact name that will be used in the `#include` directive, including the `<>` or quotes around the name.

## Contributing

We gratefully accept bugs and contributions from the community. There are some requirements we need to fulfil in order to be able to integrate contributions:

* Simple bug fixes to existing code do not contain copyright themselves and we can integrate without issue. The same is true of trivial contributions.

* For larger contributions, such as a new feature, the code can possibly fall under copyright law. We then need your consent to share in the ownership of the copyright. We have a form for this, which we will mail to you in case you submit a contribution or pull request that we deem this necessary for.

To contribute, please:

* [Check for open issues](https://github.com/ARMmbed/mbedtls/issues) or [start a discussion](https://tls.mbed.org/discussions) around a feature idea or a bug.

* Fork the [mbed TLS repository on Github](https://github.com/ARMmbed/mbedtls) to start making your changes. As a general rule, you should use the "development" branch as a basis.

* Write a test that shows that the bug was fixed or that the feature works as expected.

* Send a pull request and bug us until it gets merged and published. We will include your name in the ChangeLog :)
