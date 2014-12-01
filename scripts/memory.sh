#!/bin/sh

# Measure memory usage of a minimal client using a small configuration
# Currently hardwired to ccm-psk and suite-b, may be expanded later
#
# Use different build options for measuring executable size and memory usage,
# since for memory we want debug information.

set -eu

CONFIG_H='include/polarssl/config.h'
CLIENT='mini_client'

if [ -r $CONFIG_H ]; then :; else
    echo "$CONFIG_H not found" >&2
    exit 1
fi

if grep -i cmake Makefile >/dev/null; then
    echo "Not compatible with CMake" >&2
    exit 1
fi

if git status | grep -F $CONFIG_H >/dev/null 2>&1; then
    echo "config.h not clean" >&2
    exit 1
fi

# preparation

CONFIG_BAK=${CONFIG_H}.bak
cp $CONFIG_H $CONFIG_BAK

rm -f massif.out.*

printf "building server... "

make clean
make lib >/dev/null 2>&1
(cd programs && make ssl/ssl_server2) >/dev/null
cp programs/ssl/ssl_server2 .

echo "done"

# first config

echo ""
echo "config-ccm-psk-tls1_2:"
cp configs/config-ccm-psk-tls1_2.h $CONFIG_H

printf "    Executable size... "

make clean
CFLAGS=-fno-asynchronous-unwind-tables make OFLAGS=-Os lib >/dev/null 2>&1
cd programs
CFLAGS=-fno-asynchronous-unwind-tables make OFLAGS=-Os ssl/$CLIENT >/dev/null
strip ssl/$CLIENT
stat -c'%s' ssl/$CLIENT
cd ..

printf "    Peak ram usage... "

make clean
CFLAGS=-g3 make OFLAGS=-Os lib >/dev/null 2>&1
cd programs
CFLAGS=-g3 make OFLAGS=-Os ssl/$CLIENT >/dev/null
cd ..

./ssl_server2 psk=000102030405060708090A0B0C0D0E0F >/dev/null &
SRV_PID=$!
sleep 1;

if valgrind --tool=massif --stacks=yes programs/ssl/$CLIENT >/dev/null 2>&1
then
    FAILED=0
else
    echo "client failed" >&2
    FAILED=1
fi

kill $SRV_PID
wait $SRV_PID

scripts/massif_max.pl massif.out.*
mv massif.out.* massif-ccm-psk.$$

# second config

echo ""
echo "config-suite-b:"
cp configs/config-suite-b.h $CONFIG_H
scripts/config.pl unset POLARSSL_BASE64_C
scripts/config.pl unset POLARSSL_PEM_PARSE_C
scripts/config.pl unset POLARSSL_CERTS_C

printf "    Executable size... "

make clean
CFLAGS=-fno-asynchronous-unwind-tables make OFLAGS=-Os lib >/dev/null 2>&1
cd programs
CFLAGS=-fno-asynchronous-unwind-tables make OFLAGS=-Os ssl/$CLIENT >/dev/null
strip ssl/$CLIENT
stat -c'%s' ssl/$CLIENT
cd ..

printf "    Peak ram usage... "

make clean
CFLAGS=-g3 make OFLAGS=-Os lib >/dev/null 2>&1
cd programs
CFLAGS=-g3 make OFLAGS=-Os ssl/$CLIENT >/dev/null
cd ..

rm -f massif.out.*

./ssl_server2 >/dev/null &
SRV_PID=$!
sleep 1;

if valgrind --tool=massif --stacks=yes programs/ssl/$CLIENT >/dev/null 2>&1
then
    FAILED=0
else
    echo "client failed" >&2
    FAILED=1
fi

kill $SRV_PID
wait $SRV_PID

scripts/massif_max.pl massif.out.*
mv massif.out.* massif-suite-b.$$

# cleanup

mv $CONFIG_BAK $CONFIG_H
make clean
rm ssl_server2

exit $FAILED
