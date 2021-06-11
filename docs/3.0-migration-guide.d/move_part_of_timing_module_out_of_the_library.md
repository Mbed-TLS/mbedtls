Move part of timing module out of the library
--

The change affects users who use any of the following functions:
`mbedtls_timing_self_test()`, `mbedtls_hardclock_poll()`,
`mbedtls_timing_hardclock()` and `mbedtls_set_alarm()`.

This change is the first step of a plan of removal of the `timing.c` from the
library. The plan is to move all the timing functions to the `platform.c` file.

For users who still need removed functions the migration path is to re-implement
them as a platform support code.
