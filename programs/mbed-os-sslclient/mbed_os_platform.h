#ifndef MBED_OS_PLATFORM_H
#define MBED_OS_PLATFORM_H

typedef void * mbed_os_timing_delay_context_t;

mbed_os_timing_delay_context_t mbed_os_timing_delay_context_alloc();
void mbed_os_timing_delay_context_free( mbed_os_timing_delay_context_t );
void mbed_os_timing_delay_set( mbed_os_timing_delay_context_t );
int mbed_os_timing_delay_get( mbed_os_timing_delay_context_t );

#endif /* MBED_OS_PLATFORM_H */
