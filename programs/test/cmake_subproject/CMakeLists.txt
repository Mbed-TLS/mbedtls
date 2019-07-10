cmake_minimum_required(VERSION 2.6)

# We use the parent Mbed TLS directory as the MBEDTLS_DIR for this test. Other
# projects that use Mbed TLS as a subproject are likely to add by their own
# relative paths.
set(MBEDTLS_DIR ../../../)

# Add Mbed TLS as a subdirectory.
add_subdirectory(${MBEDTLS_DIR} build)

# Link against all the Mbed TLS libraries.
set(libs
    mbedtls
    mbedcrypto
    mbedx509
)

add_executable(cmake_subproject cmake_subproject.c)
target_link_libraries(cmake_subproject ${libs})
