add_executable(crypto_examples crypto_examples.c)
target_link_libraries(crypto_examples mbedtls)

add_executable(key_ladder_demo key_ladder_demo.c)
target_link_libraries(key_ladder_demo mbedtls)

add_executable(psa_constant_names psa_constant_names.c)
target_link_libraries(psa_constant_names mbedtls)

install(TARGETS
            crypto_examples
            key_ladder_demo
            psa_constant_names
        DESTINATION "bin"
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install(PROGRAMS
            key_ladder_demo.sh
        DESTINATION "bin")
