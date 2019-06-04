#include "common.h"

mbedtls_time_t dummy_constant_time( mbedtls_time_t* time ) {
    (void) time;
    return 0x5af2a056;
}

void dummy_init() {
#if defined(MBEDTLS_PLATFORM_TIME_ALT)
    mbedtls_platform_set_time( dummy_constant_time );
#else
    fprintf(stderr, "Warning: fuzzing without constant time\n");
#endif
}
