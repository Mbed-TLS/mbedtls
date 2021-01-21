Change the API to allow adding critical extensions to CSRs
------------------------------------------------------------------

This affects applications that call the `mbedtls_x509write_csr_set_extension`
function.

The API is changed to include the parameter `critical` which allow to mark an
extension included in a CSR as critical. To get the previous behaviour pass
`0`.
