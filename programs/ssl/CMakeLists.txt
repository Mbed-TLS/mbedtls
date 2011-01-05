add_executable(ssl_client1 ssl_client1.c)
target_link_libraries(ssl_client1 polarssl)

add_executable(ssl_client2 ssl_client2.c)
target_link_libraries(ssl_client2 polarssl)

add_executable(ssl_server ssl_server.c)
target_link_libraries(ssl_server polarssl)

INSTALL(TARGETS ssl_client1 ssl_client2 ssl_server
        DESTINATION "bin"
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
