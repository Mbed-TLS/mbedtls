add_executable(crypto_examples crypto_examples.c)
target_link_libraries(crypto_examples mbedtls)

install(TARGETS crypto_examples
        DESTINATION "bin"
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

