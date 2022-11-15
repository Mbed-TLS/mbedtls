PSA Cryptography repository
===========================
## Introduction

The PSA Cryptography repository contains a reference implementation of the [PSA Cryptography API specification](https://armmbed.github.io/mbed-crypto/psa/#application-programming-interface).

## Requirements

* The PSA Cryptography repository exposes as public interface the cryptographic interface defined in the PSA Cryptography API specification and solely this interface.
* The PSA Cryptography repository provides a way to build and test a C static and/or shared library exposing completely or partially the PSA Cryptography API.
* The PSA Cryptography repository provides a way to define the parts of the PSA Cryptography API exposed by the built C library.

* The PSA Cryptography repository is derived from the Mbed TLS repository. No cryptographic development activities as such will occur on the PSA Cryptography repository.
* The PSA Cryptography repository is derived from the Mbed TLS repository but it does not mean that all its content comes from Mbed TLS. It may contain a marginal number of files on its own.
* The PSA Cryptography repository should be able to evolve to be the development repository of the PSA Cryptography reference implementation.
* The update of the PSA Cryptography repository from the Mbed TLS repository should be automated. It is expected that the automation itself evolves with the evolutions of the Mbed TLS repository but the less the best. The trigger of the updates may not be automated.
* The testing of the PSA Cryptography repository updates should be automated (CI).
