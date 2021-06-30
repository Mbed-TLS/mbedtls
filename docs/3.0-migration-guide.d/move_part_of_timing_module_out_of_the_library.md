Move part of timing module out of the library
--

The change affects users who use any of the following functions:
`mbedtls_timing_self_test()`, `mbedtls_hardclock_poll()`,
`mbedtls_timing_hardclock()` and `mbedtls_set_alarm()`.

If you were relying on these functions, you'll now need to change to using your
platform's corresponding functions directly.
