Remove MaximumFragmentLength (MFL) query API
-----------------------------------------------------------------

This affects users which use the MFL query APIs
`mbedtls_ssl_get_{input,output}_max_frag_len()` to
infer upper bounds on the plaintext size of incoming and
outgoing record.

Users should switch to `mbedtls_ssl_get_max_{in,out}_record_payload()`
instead, which also provides such upper bounds but takes more factors
than just the MFL configuration into account.
