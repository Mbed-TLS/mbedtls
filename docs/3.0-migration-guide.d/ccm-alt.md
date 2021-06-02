CCM interface changes: impact for alternative implementations
-------------------------------------------------------------

The CCM interface has changed with the addition of support for
multi-part operations. Five new API functions have been defined:
mbedtls_ccm_starts(), mbedtls_ccm_set_lengths(),
mbedtls_ccm_update_ad(), mbedtls_ccm_update() and mbedtls_ccm_finish().
Alternative implementations of CCM (`MBEDTLS_CCM_ALT`) have now to
implement those additional five API functions.
