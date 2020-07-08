#!/bin/bash

echo "Performing build"
mkdir -p build
cd build
cmake -DCMAKE_SYSTEM_NAME=Android -DCMAKE_SYSTEM_VERSION=1 \
  -DCMAKE_LINKER=/opt/android-ndk-r20b/android-ndk-r20b/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android-ld \
  -DCMAKE_C_COMPILER=/opt/android-ndk-r20b/android-ndk-r20b/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android24-clang \
  -DCMAKE_CXX_COMPILER=/opt/android-ndk-r20b/android-ndk-r20b/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android24-clang++ \
  ..
cd -
cmake --build ./build -- -j`nproc`
