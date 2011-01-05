OPTION(USE_SHARED_POLARSSL_LIBRARY "Build PolarSSL as a shared library." OFF)

set(src
     aes.c
     arc4.c
     base64.c
     bignum.c
     camellia.c
     certs.c
     debug.c
     des.c
     dhm.c
     havege.c
     md2.c
     md4.c
     md5.c
     net.c
     padlock.c
     rsa.c
     sha1.c
     sha2.c
     sha4.c
     ssl_cli.c 
     ssl_srv.c 
     ssl_tls.c
     timing.c
     version.c
     x509parse.c
     xtea.c
)

if(NOT USE_SHARED_POLARSSL_LIBRARY)

add_library(polarssl STATIC ${src})

else(NOT USE_SHARED_POLARSSL_LIBRARY)

ADD_LIBRARY(polarssl SHARED ${src})
SET_TARGET_PROPERTIES(polarssl PROPERTIES VERSION 0.14.1 SOVERSION 0)

endif(NOT USE_SHARED_POLARSSL_LIBRARY)

INSTALL(TARGETS polarssl
        DESTINATION lib
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
