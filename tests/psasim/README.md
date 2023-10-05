# psasim

This is a library that simulates a PSA Firmware Framework compliant implementation.
It allows you to develop secure partitions and their clients on a desktop computer.
It should be able to run on all systems that support POSIX and System V IPC:
e.g. macOS, Linux, FreeBSD, and perhaps Windows 10 WSL2. 

To build and run the test program make sure you have `make`, `python` and a 
C compiler installed and then enter the following commands:

```sh
make install
make run
```

On Linux you may need to run `ldconfig` to ensure the library is properly installed.

An example pair of programs is included in the **test** directory.

The implemented API is compliant with PSA-FF 1.0.0 with the exception of 
a couple of things that are a work in progress:

* `psa_notify` support
* "strict" policy in manifest

The only supported "interrupts" are POSIX signals, which act
as a "virtual interrupt" :-)

The standard PSA RoT APIs are not included (e.g. cryptography, attestation, lifecycle etc). 

## Design

The code is designed to be readable rather than fast.
In this implementation only one message is delivered to a 
RoT service at a time.
Things that need to be done to improve this implementation:

* run against the official test suite
* make thread safe
* make code more readable
* improve quality of code
* man pages
* use sockets for message passing (WSL doesn't support System V message queues)
* general robustness and hardening

To debug the simulator enable the debug flag:

```sh
make DEBUG=1 install
```

## Unsupported features

Because this is a simulator there are a few things that
can't be reasonably emulated:

* Manifest MMIO regions are unsupported
* Manifest priority field is ignored 
* Partition IDs are in fact POSIX `pid_t`, which are only assigned at runtime, 
  making it infeasible to populate pid.h with correct values. 
