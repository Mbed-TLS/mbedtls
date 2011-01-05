add_executable(cert_app cert_app.c)
target_link_libraries(cert_app polarssl)

INSTALL(TARGETS cert_app
        DESTINATION "bin"
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
