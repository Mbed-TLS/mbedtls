
extern "C" {
#include "mbedtls/serialize.h"
}
#include "RawSerial.h"

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

