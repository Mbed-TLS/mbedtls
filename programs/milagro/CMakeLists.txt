set(THREADS_USE_PTHREADS_WIN32 true)
find_package(Threads)

set(libs
    mbedtls
    amcl
    mpin
    wcc
)

set(targets
    TA_cs
    TA_p2p 
    tls_client  
    tls_server
)

if(USE_PKCS11_HELPER_LIBRARY)
    set(libs ${libs} pkcs11-helper)
endif(USE_PKCS11_HELPER_LIBRARY)

if(ENABLE_ZLIB_SUPPORT)
    set(libs ${libs} ${ZLIB_LIBRARIES})
endif(ENABLE_ZLIB_SUPPORT)

add_executable(TA_cs TA_cs.c)
target_link_libraries(TA_cs ${libs})

add_executable(TA_p2p TA_p2p.c)
target_link_libraries(TA_p2p ${libs})

add_executable(tls_server tls_server.c)
target_link_libraries(tls_server ${libs})

add_executable(tls_client tls_client.c)
target_link_libraries(tls_client ${libs})

install(TARGETS ${targets}
        DESTINATION "bin"
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
