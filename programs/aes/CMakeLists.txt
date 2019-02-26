add_executable(crypt_and_hash crypt_and_hash.c)
target_link_libraries(crypt_and_hash mbedtls)

install(TARGETS crypt_and_hash
        DESTINATION "bin"
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
