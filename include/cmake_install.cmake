# Install script for directory: /home/jordan/mbedtls/include

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr/local")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Install shared libraries without execute permission?
if(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
  set(CMAKE_INSTALL_SO_NO_EXE "1")
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/mbedtls" TYPE FILE PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ FILES
    "/home/jordan/mbedtls/include/mbedtls/aes.h"
    "/home/jordan/mbedtls/include/mbedtls/aesni.h"
    "/home/jordan/mbedtls/include/mbedtls/arc4.h"
    "/home/jordan/mbedtls/include/mbedtls/asn1.h"
    "/home/jordan/mbedtls/include/mbedtls/asn1write.h"
    "/home/jordan/mbedtls/include/mbedtls/base64.h"
    "/home/jordan/mbedtls/include/mbedtls/bignum.h"
    "/home/jordan/mbedtls/include/mbedtls/blowfish.h"
    "/home/jordan/mbedtls/include/mbedtls/bn_mul.h"
    "/home/jordan/mbedtls/include/mbedtls/camellia.h"
    "/home/jordan/mbedtls/include/mbedtls/ccm.h"
    "/home/jordan/mbedtls/include/mbedtls/certs.h"
    "/home/jordan/mbedtls/include/mbedtls/check_config.h"
    "/home/jordan/mbedtls/include/mbedtls/cipher.h"
    "/home/jordan/mbedtls/include/mbedtls/cipher_internal.h"
    "/home/jordan/mbedtls/include/mbedtls/cmac.h"
    "/home/jordan/mbedtls/include/mbedtls/compat-1.3.h"
    "/home/jordan/mbedtls/include/mbedtls/config.h"
    "/home/jordan/mbedtls/include/mbedtls/ctr_drbg.h"
    "/home/jordan/mbedtls/include/mbedtls/debug.h"
    "/home/jordan/mbedtls/include/mbedtls/des.h"
    "/home/jordan/mbedtls/include/mbedtls/dhm.h"
    "/home/jordan/mbedtls/include/mbedtls/ecdh.h"
    "/home/jordan/mbedtls/include/mbedtls/ecdsa.h"
    "/home/jordan/mbedtls/include/mbedtls/ecjpake.h"
    "/home/jordan/mbedtls/include/mbedtls/ecp.h"
    "/home/jordan/mbedtls/include/mbedtls/entropy.h"
    "/home/jordan/mbedtls/include/mbedtls/entropy_poll.h"
    "/home/jordan/mbedtls/include/mbedtls/error.h"
    "/home/jordan/mbedtls/include/mbedtls/gcm.h"
    "/home/jordan/mbedtls/include/mbedtls/havege.h"
    "/home/jordan/mbedtls/include/mbedtls/hmac_drbg.h"
    "/home/jordan/mbedtls/include/mbedtls/md.h"
    "/home/jordan/mbedtls/include/mbedtls/md2.h"
    "/home/jordan/mbedtls/include/mbedtls/md4.h"
    "/home/jordan/mbedtls/include/mbedtls/md5.h"
    "/home/jordan/mbedtls/include/mbedtls/md_internal.h"
    "/home/jordan/mbedtls/include/mbedtls/memory_buffer_alloc.h"
    "/home/jordan/mbedtls/include/mbedtls/net.h"
    "/home/jordan/mbedtls/include/mbedtls/net_sockets.h"
    "/home/jordan/mbedtls/include/mbedtls/oid.h"
    "/home/jordan/mbedtls/include/mbedtls/padlock.h"
    "/home/jordan/mbedtls/include/mbedtls/pem.h"
    "/home/jordan/mbedtls/include/mbedtls/pk.h"
    "/home/jordan/mbedtls/include/mbedtls/pk_internal.h"
    "/home/jordan/mbedtls/include/mbedtls/pkcs11.h"
    "/home/jordan/mbedtls/include/mbedtls/pkcs12.h"
    "/home/jordan/mbedtls/include/mbedtls/pkcs5.h"
    "/home/jordan/mbedtls/include/mbedtls/platform.h"
    "/home/jordan/mbedtls/include/mbedtls/platform_time.h"
    "/home/jordan/mbedtls/include/mbedtls/ripemd160.h"
    "/home/jordan/mbedtls/include/mbedtls/rsa.h"
    "/home/jordan/mbedtls/include/mbedtls/sha1.h"
    "/home/jordan/mbedtls/include/mbedtls/sha256.h"
    "/home/jordan/mbedtls/include/mbedtls/sha512.h"
    "/home/jordan/mbedtls/include/mbedtls/ssl.h"
    "/home/jordan/mbedtls/include/mbedtls/ssl_cache.h"
    "/home/jordan/mbedtls/include/mbedtls/ssl_ciphersuites.h"
    "/home/jordan/mbedtls/include/mbedtls/ssl_cookie.h"
    "/home/jordan/mbedtls/include/mbedtls/ssl_internal.h"
    "/home/jordan/mbedtls/include/mbedtls/ssl_ticket.h"
    "/home/jordan/mbedtls/include/mbedtls/threading.h"
    "/home/jordan/mbedtls/include/mbedtls/timing.h"
    "/home/jordan/mbedtls/include/mbedtls/version.h"
    "/home/jordan/mbedtls/include/mbedtls/x509.h"
    "/home/jordan/mbedtls/include/mbedtls/x509_crl.h"
    "/home/jordan/mbedtls/include/mbedtls/x509_crt.h"
    "/home/jordan/mbedtls/include/mbedtls/x509_csr.h"
    "/home/jordan/mbedtls/include/mbedtls/xtea.h"
    )
endif()

