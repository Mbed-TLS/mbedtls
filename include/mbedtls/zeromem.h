 /* Implementation that should never be optimized out by the compiler */
#ifdef _MSC_VER
#define mbedtls_zeroize RtlSecureZeroMemory
#else
void mbedtls_zeroize( void *v, size_t n );
#endif 