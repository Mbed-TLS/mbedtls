#!/bin/sh


MBEDTLS_ROOT=$(pwd)
ON_TARGET_PROG_DIR=$MBEDTLS_ROOT/programs/otst
MBEDTLS_IMPORTER_DIR=$ON_TARGET_PROG_DIR/mbed-os/features/mbedtls/importer/
ON_TARGET_MBEDTLS_CONFIG=$ON_TARGET_PROG_DIR/mbed-os/features/mbedtls/inc/mbedtls/config.h

./scripts/

rm -rf $ON_TARGET_PROG_DIR
mkdir $ON_TARGET_PROG_DIR

#cd $ON_TARGET_PROG_DIR
#git clone git@github.com:ARMmbed/mbed-os.git
cp $1 -r  $ON_TARGET_PROG_DIR

ln -s $MBEDTLS_ROOT $MBEDTLS_IMPORTER_DIR/TARGET_IGNORE/mbedtls
cd $MBEDTLS_IMPORTER_DIR
make deploy
cd $MBEDTLS_ROOT
./scripts/config.pl -f $ON_TARGET_MBEDTLS_CONFIG set MBEDTLS_SERIALIZE_C
./scripts/config.pl -f $ON_TARGET_MBEDTLS_CONFIG set MBEDTLS_FS_IO

cp programs/on-target/main.c $ON_TARGET_PROG_DIR
cd $ON_TARGET_PROG_DIR
mbed-cli config root .
mbed-cli compile -m K64F -t GCC_ARM

