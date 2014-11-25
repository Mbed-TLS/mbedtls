#!/bin/sh

# Measure memory usage of a minimal client using a small configuration
# Currently hardwired to the ccm-psk configuration, may be expanded later

set -eu

CONFIG_H='include/polarssl/config.h'
CLIENT='mini_client'

if [ -r $CONFIG_H ]; then :; else
    echo "$CONFIG_H not found" >&2
    exit 1
fi

CONFIG_BAK=${CONFIG_H}.bak
cp $CONFIG_H $CONFIG_BAK

cp configs/config-ccm-psk-tls1_2.h $CONFIG_H

printf "Executable size... "

make clean
CFLAGS=-fno-asynchronous-unwind-tables make OFLAGS=-Os lib >/dev/null 2>&1
cd programs
CFLAGS=-fno-asynchronous-unwind-tables make OFLAGS=-Os ssl/$CLIENT >/dev/null
strip ssl/$CLIENT
stat -c'%s' ssl/$CLIENT
cd ..

printf "Peak ram usage... "

make clean
CFLAGS=-g3 make OFLAGS=-Os lib >/dev/null 2>&1
cd programs
CFLAGS=-g3 make OFLAGS=-Os ssl/$CLIENT ssl/ssl_server2 >/dev/null
cd ..

rm -f massif.out.*

programs/ssl/ssl_server2 psk=000102030405060708090A0B0C0D0E0F >/dev/null &
SRV_PID=$!
sleep 1;

if valgrind --tool=massif --stacks=yes programs/ssl/$CLIENT > /dev/null 2>&1
then
    FAILED=0
else
    echo "client failed" >&2
    FAILED=1
fi

kill $SRV_PID
wait $SRV_PID

scripts/massif_max.pl massif.out.*

rm -f massif.out.*
mv $CONFIG_BAK $CONFIG_H

exit $FAILED
