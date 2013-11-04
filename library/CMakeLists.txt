option(USE_SHARED_POLARSSL_LIBRARY "Build PolarSSL as a shared library." OFF)

set(src
     aes.c
     arc4.c
     asn1parse.c
     asn1write.c
     base64.c
     bignum.c
     blowfish.c
     camellia.c
     certs.c
     cipher.c
     cipher_wrap.c
     ctr_drbg.c
     debug.c
     des.c
     dhm.c
     ecp.c
     ecdh.c
     ecdsa.c
     entropy.c
     entropy_poll.c
     error.c
     gcm.c
     havege.c
     md.c
     md_wrap.c
     md2.c
     md4.c
     md5.c
     memory.c
     memory_buffer_alloc.c
     net.c
     oid.c
     padlock.c
     pbkdf2.c
     pem.c
     pkcs5.c
     pkcs11.c
     pkcs12.c
     pk.c
     pk_wrap.c
     pkparse.c
     pkwrite.c
     rsa.c
     sha1.c
     sha256.c
     sha512.c
     ssl_cache.c
     ssl_ciphersuites.c
     ssl_cli.c
     ssl_srv.c
     ssl_tls.c
     threading.c
     timing.c
     version.c
     x509.c
     x509_crt.c
     x509_crl.c
     x509_csr.c
     x509_create.c
     x509write_crt.c
     x509write_csr.c
     xtea.c
)

if(WIN32)
set(libs ws2_32)
endif(WIN32)

if(NOT USE_SHARED_POLARSSL_LIBRARY)

add_library(polarssl STATIC ${src})

else(NOT USE_SHARED_POLARSSL_LIBRARY)

add_library(polarssl SHARED ${src})
set_target_properties(polarssl PROPERTIES VERSION 1.3.2 SOVERSION 5)

endif(NOT USE_SHARED_POLARSSL_LIBRARY)

target_link_libraries(polarssl ${libs})

install(TARGETS polarssl
        DESTINATION ${LIB_INSTALL_DIR}
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
