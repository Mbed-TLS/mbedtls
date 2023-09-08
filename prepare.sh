#/bin/bash

set -e;

BUILD_DIR=build;

if [ ! -d ${BUILD_DIR} ] ; then
	mkdir ${BUILD_DIR};
fi

if [ ! -d ${BUILD_DIR} ] ; then
	faildir=`pwd`/${BUILD_DIR};
	echo "!!! Could not create $faildir !!!";
	exit -1;
fi

pushd ${BUILD_DIR};
	cmake -DCMAKE_TOOLCHAIN_FILE=../toolchain_solo.cmake ../
popd;
