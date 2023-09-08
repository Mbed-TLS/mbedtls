# taken from:
# https://cmake.org/cmake/help/v3.12/manual/cmake-toolchains.7.html#cross-compiling-for-linux
# and adapted

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR arm)
set(CROSSCOMPILE)

find_file(
      TI_SDK_PARENT "ti-sdk"
      PATHS "$ENV{OPT_DIR}" "/home/sumup/" "${TI_SDK_PARENT}"
      )
if ("${TI_SDK_PARENT}" STREQUAL "TI_SDK_PARENT-NOTFOUND")
   message(FATAL_ERROR "ti-sdk not found!")
else ()
   set(ti_sdk "${TI_SDK_PARENT}")
   message("ti_sdk: ${ti_sdk}")
endif ()

set(tools ${ti_sdk}/linux-devkit/sysroots/x86_64-arago-linux/usr/bin)
set(CMAKE_C_COMPILER "${tools}/arm-linux-gnueabihf-gcc")
set(CMAKE_AR "${tools}/arm-linux-gnueabihf-ar")
set(CMAKE_RANLIB "${tools}/arm-linux-gnueabihf-ranlib")

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
set(LIBNL_PATH ${ti_sdk}/linux-devkit/sysroots/armv7ahf-neon-linux-gnueabi/usr/lib)
set(LIBNL_INCLUDE_PATH ${ti_sdk}/linux-devkit/sysroots/armv7ahf-neon-linux-gnueabi/usr/include/libnl3)
add_compile_options(-Wall -Wextra -Werror -Wshadow -fpic -Wno-unused-function)

