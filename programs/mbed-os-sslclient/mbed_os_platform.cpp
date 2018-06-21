#include "mbed.h"
#include "drivers/TimerEvent.h"
#include "RawSerial.h"

extern "C" {
#include "mbedtls/serialize.h"
}

using namespace mbed;

class MyTimer: public TimerEvent
{
public:
    MyTimer(): TimerEvent(), int_us(0), fin_us(0), state(0){}

    void reset()
    {
        int_us = 0;
        fin_us = 0;
        state = 0;
    }

    void handler()
    {
        state++;

        if( state == 1 )
        {
            if( int_us < fin_us )
            {
                // intermediate delay passed.
                insert_absolute(event.timestamp + (fin_us - int_us));
            }
            else
                state++;
        }
    }
    void set_delay(uint32_t int_ms, uint32_t fin_ms)
    {
        if( fin_ms == 0 )
        {
            remove();
            state = -1;
        }
        else
        {
            // int_us == 0 implies that intermediate delay has passed.
            int_us = int_ms * 1000;
            fin_us = fin_ms * 1000;
            state = (int_us == 0)?1:0;
            uint64_t min = (int_us && int_us < fin_us)?int_us:fin_us;
            insert(min);
        }
    }
    int get_delay()
    {
        return state;
    }
    uint64_t int_us;
    uint64_t fin_us;
    int state;
};

mbed_os_timing_delay_context_t mbed_os_timing_delay_context_alloc()
{
    return (mbed_os_timing_delay_context_t)(new MyTimer());
}

void mbed_os_timing_delay_context_free( mbed_os_timing_delay_context_t timer )
{
    delete ( ( MyTimer *) timer );
}

void mbed_os_timing_delay_set( mbed_os_timing_delay_context_t timer, uint32_t int_ms, uint32_t fin_ms )
{
    ( ( MyTimer *) timer )->set_delay( int_ms, fin_ms );
}

int mbed_os_timing_delay_get( mbed_os_timing_delay_context_t timer )
{
    return ( ( MyTimer *) timer )->get_delay();
}


static mbed::RawSerial serial = mbed::RawSerial(USBTX, USBRX, MBED_CONF_PLATFORM_STDIO_BAUD_RATE);

int mbedtls_serialize_write( const uint8_t *buffer, size_t length )
{
    ssize_t offset = 0;
    for(int i = 0; i < 2;i++)
    {
        if(serial.putc('{') == -1)
            return MBEDTLS_ERR_SERIALIZE_SEND;
    }
    while(offset < length && serial.putc(buffer[offset++]) != -1);
    return (offset == length)?0:MBEDTLS_ERR_SERIALIZE_SEND;
}

int mbedtls_serialize_read( uint8_t *buffer, size_t length )
{
    ssize_t offset = 0;
    int c;
    while(offset < length && (c = serial.getc()) != EOF)
        buffer[offset++] = (char)c;
    return (offset == length)?0:MBEDTLS_ERR_SERIALIZE_RECEIVE;
}

