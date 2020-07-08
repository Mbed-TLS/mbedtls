#!/bin/bash

echo "Performing build"
mkdir -p build
cd build
cmake -DCMAKE_SYSTEM_NAME=Android -DCMAKE_SYSTEM_VERSION=1 \
  -DCMAKE_TOOLCHAIN_FILE=${ANDROID_NDK_HOME}/build/cmake/android.toolchain.cmake \
  -DANDROID_ABI=${ANDROID_ABI} \
  -DANDROID_NATIVE_API_LEVEL=${ANDROID_PLATFORM} \
  ..
cd -
cmake --build ./build -- -j`nproc`
