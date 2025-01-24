API changes
   * The PSA and Mbed TLS error space are now unified. This means that
     mbedtls_xxx() functions can return PSA_ERROR_xxx values.
     There is no longer a distinction between "low-level" and "high-level"
     Mbed TLS error codes..
     This will not affect most applications since in both cases, the
     error values are between -32767 and -1 as before.
