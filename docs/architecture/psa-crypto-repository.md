PSA Cryptography repository
===========================
## Introduction

The PSA Cryptography repository contains a reference implementation of the [PSA Cryptography API and its unified driver interface](https://armmbed.github.io/mbed-crypto/psa/#application-programming-interface). This encompasses the on-going extensions to the PSA Cryptography API like currently PAKE.

## Requirements

* The PSA Cryptography repository exposes as public interface the cryptographic interface defined in the PSA Cryptography API specification and solely this interface.
* The PSA Cryptography repository provides a way to independently build and test a C static and/or shared library exposing completely or partially the PSA Cryptography API, without relying on the Mbed TLS repository.
* The PSA Cryptography repository provides a configuration mechanism to define the parts of the PSA Cryptography API exposed by the built C library.

* The PSA Cryptography repository is derived from the Mbed TLS repository. No cryptographic development activities as such will occur on the PSA Cryptography repository.
* The PSA Cryptography repository is derived from the Mbed TLS repository but it does not mean that all its content comes from Mbed TLS. It may contain a marginal number of files on its own.
* The PSA Cryptography repository must be able to evolve to be the development repository of the PSA Cryptography reference implementation.
* The update of the PSA Cryptography repository from the Mbed TLS repository should be automated and done at a reasonably short cadence (i.e, at least monthly). It is expected that the automation itself evolves with the evolutions of the Mbed TLS repository but the less the better. The trigger of the updates may or may not be automated.
* The testing of the PSA Cryptography repository updates should be automated (CI).
