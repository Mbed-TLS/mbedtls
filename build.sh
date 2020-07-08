#!/bin/bash

echo "Performing build"
mkdir -p build
cmake -DCMAKE_SYSTEM_NAME=Android -DCMAKE_SYSTEM_VERSION=1 \
  -DCMAKE_C_COMPILER=/opt/android-ndk-r20b/android-ndk-r20b/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android24-clang \
  -DCMAKE_CXX_COMPILER=/opt/android-ndk-r20b/android-ndk-r20b/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android24-clang++ \
  -B build -S .
cmake --build ./build -- -j`nproc`
