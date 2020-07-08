#!/bin/bash

echo "Renaming asset to a descriptive filename"
BUILD_TIME=`date +%F_%T`
FILENAME=/opt/mbedtls-${TARGET}-${DRONE_SOURCE_BRANCH}-${BUILD_TIME}-${DRONE_COMMIT_SHA:0:8}.tar.gz

mkdir -p mbedtls/include
cp -R include/mbedtls/*.h mbedtls/include
mkdir -p mbedtls/lib
cp build/library/*.a mbedtls/lib

tar -czvf mbedtls.tar.gz mbedtls/
cp mbedtls.tar.gz $FILENAME
echo "New filename: " $FILENAME

echo "Some useful env info"
curl --version
ls -l $FILENAME

echo "Uploading asset to Nexus"
curl -v --user "vhtest:$NEXUS_PWD" --upload-file $FILENAME https://nexus.mersive.xyz/repository/vhserver/${DRONE_SOURCE_BRANCH}/
