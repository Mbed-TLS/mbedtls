What is it?
------

This directory contains fuzz targets.
Fuzz targets are simple codes using the library.
They are used with a so-called fuzz driver, which will generate inputs, try to process them with the fuzz target, and alert in case of an unwanted behavior (such as a buffer overflow for instance).

These targets were meant to be used with oss-fuzz but can be used in other contexts.

This code was contributed by Philippe Antoine ( Catena cyber ).

How to run?
------

To run the fuzz targets like oss-fuzz:
```
git clone https://github.com/google/oss-fuzz
cd oss-fuzz
python infra/helper.py build_image mbedtls
python infra/helper.py build_fuzzers --sanitizer address mbedtls
python infra/helper.py run_fuzzer mbedtls fuzz_client
```
You can use `undefined` sanitizer as well as `address` sanitizer.
And you can run any of the fuzz targets like `fuzz_client`.

To run the fuzz targets without oss-fuzz, you first need to install one libFuzzingEngine (libFuzzer for instance).
Then you need to compile the code with the compiler flags of the wished sanitizer.
```
perl scripts/config.pl set MBEDTLS_PLATFORM_TIME_ALT
mkdir build
cd build
cmake ..
make
```
Finally, you can run the targets like `./test/fuzz/fuzz_client`.
