set(executables
    crypto_examples
    key_ladder_demo
    psa_constant_names
)

foreach(exe IN LISTS executables)
    add_executable(${exe} ${exe}.c)
    target_link_libraries(${exe} mbedtls)
endforeach()

target_include_directories(psa_constant_names PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

add_custom_target(
    psa_constant_names_generated
    COMMAND ${MBEDTLS_PYTHON_EXECUTABLE} scripts/generate_psa_constants.py ${CMAKE_CURRENT_BINARY_DIR}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/../../
)
add_dependencies(psa_constant_names psa_constant_names_generated)

install(TARGETS ${executables}
        DESTINATION "bin"
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install(PROGRAMS
            key_ladder_demo.sh
        DESTINATION "bin")
