add_executable(crypto_examples crypto_examples.c)
target_link_libraries(crypto_examples mbedcrypto)

add_executable(key_ladder_demo key_ladder_demo.c)
target_link_libraries(key_ladder_demo mbedcrypto)

add_executable(psa_constant_names psa_constant_names.c)
target_link_libraries(psa_constant_names mbedcrypto)

add_custom_target(
    psa_constant_names_generated
    COMMAND ${PYTHON_EXECUTABLE} scripts/generate_psa_constants.py
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/../../
)
add_dependencies(psa_constant_names psa_constant_names_generated)

install(TARGETS
            crypto_examples
            key_ladder_demo
            psa_constant_names
        DESTINATION "bin"
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install(PROGRAMS
            key_ladder_demo.sh
        DESTINATION "bin")
