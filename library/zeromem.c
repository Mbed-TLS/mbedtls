#ifndef _MSC_VER
/* Implementation that should never be optimized out by the compiler */
void mbedtls_zeroize( void *v, size_t n ) {
    volatile char *p = (char *)v; while( n-- ) *p++ = 0;
}
#endif