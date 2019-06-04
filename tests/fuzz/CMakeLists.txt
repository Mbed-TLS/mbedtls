set(libs
    mbedtls
)

if(USE_PKCS11_HELPER_LIBRARY)
    set(libs ${libs} pkcs11-helper)
endif(USE_PKCS11_HELPER_LIBRARY)

if(ENABLE_ZLIB_SUPPORT)
    set(libs ${libs} ${ZLIB_LIBRARIES})
endif(ENABLE_ZLIB_SUPPORT)

add_executable(fuzz_x509csr fuzz_x509csr.c onefile.c)
target_link_libraries(fuzz_x509csr ${libs})

add_executable(fuzz_x509crl fuzz_x509crl.c onefile.c)
target_link_libraries(fuzz_x509crl ${libs})

add_executable(fuzz_x509crt fuzz_x509crt.c onefile.c)
target_link_libraries(fuzz_x509crt ${libs})

add_executable(fuzz_privkey fuzz_privkey.c onefile.c)
target_link_libraries(fuzz_privkey ${libs})

add_executable(fuzz_pubkey fuzz_pubkey.c onefile.c)
target_link_libraries(fuzz_pubkey ${libs})

add_executable(fuzz_client fuzz_client.c common.c onefile.c)
target_link_libraries(fuzz_client ${libs})

add_executable(fuzz_server fuzz_server.c common.c onefile.c)
target_link_libraries(fuzz_server ${libs})

add_executable(fuzz_dtlsclient fuzz_dtlsclient.c common.c onefile.c)
target_link_libraries(fuzz_dtlsclient ${libs})

add_executable(fuzz_dtlsserver fuzz_dtlsserver.c common.c onefile.c)
target_link_libraries(fuzz_dtlsserver ${libs})
