set(libs
     polarssl
)

if(USE_PKCS11_HELPER_LIBRARY)
    set(libs ${libs} pkcs11-helper)
endif(USE_PKCS11_HELPER_LIBRARY)

add_executable(ssl_client1 ssl_client1.c)
target_link_libraries(ssl_client1 ${libs})

add_executable(ssl_client2 ssl_client2.c)
target_link_libraries(ssl_client2 ${libs})

add_executable(ssl_server ssl_server.c)
target_link_libraries(ssl_server ${libs})

add_executable(ssl_fork_server ssl_fork_server.c)
target_link_libraries(ssl_fork_server ${libs})

add_executable(ssl_mail_client ssl_mail_client.c)
target_link_libraries(ssl_mail_client ${libs})

INSTALL(TARGETS ssl_client1 ssl_client2 ssl_server ssl_fork_server ssl_mail_client
        DESTINATION "bin"
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
