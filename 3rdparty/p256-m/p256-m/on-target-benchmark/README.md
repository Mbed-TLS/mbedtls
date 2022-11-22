How to build and run the p256-m benchmark on Mbed-enabled targets
=================================================================

First time
----------

- Make sure you have the `arm-none-eabi` GCC-based toolchain installed:
  https://developer.arm.com/tools-and-software/open-source-software/developer-tools/gnu-toolchain/gnu-rm/downloads
- Install mbed-cli:
  https://os.mbed.com/docs/mbed-os/v6.2/quick-start/build-with-mbed-cli.html
- Give your user permission to access the serial port associated to your
  device (on my Ubuntu 20.04 machine, that's `/dev/ttyACM0` and I needed to
add myself to the `dialout` group and log in again).
- Run `mbed deploy` in this directory.

Every time / for each target
----------------------------

- Run `make test-data.h` in the parent directory.
- Connect your Mbed-enabled board to your computer.
- Run `mbed compile -m <your_target> -t GCC_ARM --profile release --flash --sterm`.
- If the `--flash` or `--sterm` options didn't work, you can manually:
  - Copy the generated `.bin` file whose location was shown by `mbed compile`
    to the directory where your target is mounter.
  - Open your favourite serial terminal emulator to the connected device.
  - Hit the reset button on your board if necessary.

The benchmark program should complete in a few (dozen) seconds.
