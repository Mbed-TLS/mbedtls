# Mbed Crypto driver interface test strategy

This document describes the test strategy for the driver interfaces in Mbed Crypto. Mbed Crypto has interfaces for secure element drivers, accelerator drivers and entropy drivers. This document is about testing Mbed Crypto itself; testing drivers is out of scope.

The driver interfaces are standardized through PSA Cryptography functional specifications.

## Secure element driver interface

The secure element driver interface (SE interface for short) is defined by [`psa/crypto_se_driver.h`](../../../include/psa/crypto_se_driver.h). This is an interface between Mbed Crypto and one or more third-party drivers.

TODO


## Accelerator driver interface

The accelerator driver interface is defined by [`psa/crypto_accel_driver.h`](../../../include/psa/crypto_accel_driver.h).

TODO

## Entropy driver interface

The entropy driver interface is defined by [`psa/crypto_entropy_driver.h`](../../../include/psa/crypto_entropy_driver.h).

TODO
