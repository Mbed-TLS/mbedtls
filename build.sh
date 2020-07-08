#!/bin/bash

echo "Performing build"
mkdir -p build
cd build
cmake -DCMAKE_SYSTEM_NAME=Android -DCMAKE_SYSTEM_VERSION=1 \
  -DCMAKE_TOOLCHAIN_FILE=/opt/android-ndk-r20b/android-ndk-r20b/build/cmake/android.toolchain.cmake \
  -DANDROID_ABI=arm64-v8a \
  -DANDROID_NATIVE_API_LEVEL=25 \
  ..
cd -
cmake --build ./build -- -j`nproc`
