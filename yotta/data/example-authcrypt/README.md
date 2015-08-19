# Authenticated encryption example

This application performs authenticated encryption and authenticated decryption of a buffer. It serves as a tutorial for the basic authenticated encryption functions of mbed TLS.

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

4. Build mbedtls and the examples. This will take a long time if it is the first time:

    ```
    $ yt build
    ```

5. Copy `build/frdm-k64f-gcc/test/mbedtls-test-example-authcrypt.bin` to your mbed board and wait until the LED next to the USB port stops blinking.

6. Start the serial terminal emulator and connect to the virtual serial port presented by FRDM-K64F. For settings, use 115200 baud, 8N1, no flow control. **Warning:** for this example, the baud rate is not the default 9600, it is 115200.

7. Press the reset button on the board.

8. The output in the terminal window should look like:

    ```
    {{timeout;10}}
    {{host_test_name;default}}
    {{description;mbed TLS example authcrypt}}
    {{test_id;MBEDTLS_EX_AUTHCRYPT}}
    {{start}}


    plaintext message: 536f6d65207468696e67732061726520626574746572206c65667420756e7265616400
    ciphertext: c57f7afb94f14c7977d785d08682a2596bd62ee9dcf216b8cccd997afee9b402f5de1739e8e6467aa363749ef39392e5c66622b01c7203ec0a3d14
    decrypted: 536f6d65207468696e67732061726520626574746572206c65667420756e7265616400

    DONE
    {{success}}
    {{end}}
    ```

The actual output  for the ciphertext line will vary on each run due to the use of a random nonce in the encryption process.
