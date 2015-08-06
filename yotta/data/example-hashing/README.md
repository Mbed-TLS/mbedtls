# Hashing tutorial

This application performs hashing of a buffer with SHA-256 using various APIs. It serves as a tutorial for the basic hashing APIs of mbed TLS.

## Pre-requisites

To build and run this example the requirements below are necessary:

* A computer with the following software installed:
  * [CMake](http://www.cmake.org/download/).
  * [yotta](https://github.com/ARMmbed/yotta). Please note that **yotta has its own set of dependencies**, listed in the [installation instructions](http://armmbed.github.io/yotta/#installing-on-windows).
  * [Python](https://www.python.org/downloads/).
  * [ARM GCC toolchain](https://launchpad.net/gcc-arm-embedded).
  * A serial terminal emulator (e.g. screen, pySerial, cu).
* An [FRDM-K64F](http://developer.mbed.org/platforms/FRDM-K64F/) development board, or another board supported by mbed OS (in that case you'll have to substitute frdm-k64f-gcc with the appropriate target below).
* A micro-USB cable.
* If your OS is Windows, please follow the installation instructions [for the serial port driver](https://developer.mbed.org/handbook/Windows-serial-configuration).

## Getting started

1. Connect the FRDM-K64F to the computer with the micro-USB cable, being careful to use the micro-usb port labeled "OpenSDA".

2. Navigate to the mbedtls directory supplied with your release and open a terminal.

3. Set the yotta target:

    ```
    yotta target frdm-k64f-gcc
    ```

4. Check that there are no missing dependencies:

    ```
    $ yt ls
    ```

    If there are, yotta will list them in the terminal. Please install them before proceeding.

5. Build mbedtls and the examples. This will take a long time if it is the first time:

    ```
    $ yt build
    ```

6. Copy `build/frdm-k64f-gcc/test/mbedtls-test-example-hashing.bin` to your mbed board and wait until the LED next to the USB port stops blinking.

7. Start the serial terminal emulator and connect to the virtual serial port presented by FRDM-K64F. For settings, use 9600 baud, 8N1, no flow control.

8. Press the reset button on the board.

9. The output in the terminal window should look like:

    ```
    {{timeout;10}}
    {{host_test_name;default}}
    {{description;mbed TLS example on hashing}}
    {{test_id;MBEDTLS_EX_HASHING}}
    {{start}}


    Method 1: 315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3
    Method 2: 315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3
    Method 3: 315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3
    Method 4: 315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3

    DONE
    {{success}}
    {{end}}
    ```
