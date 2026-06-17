cmake_minimum_required(VERSION 3.5.1)

# Test the target renaming support by adding a prefix to the targets built
set(MBEDTLS_TARGET_PREFIX subproject_test_)

# We use the parent Mbed TLS directory as the MBEDTLS_DIR for this test. Other
# projects that use Mbed TLS as a subproject are likely to add by their own
# relative paths.
set(MBEDTLS_DIR ../../../)
# Use the local `custom` directory for the crypto dispatch implementation
set(TF_PSA_CRYPTO_DISPATCH_DIR ${CMAKE_CURRENT_LIST_DIR}/custom)

# Add Mbed TLS as a subdirectory.
add_subdirectory(${MBEDTLS_DIR} build)

add_executable(cmake_subproject_custom_dispatch cmake_subproject_dispatch.c)
target_link_libraries(cmake_subproject_custom_dispatch
    subproject_test_mbedtls
    subproject_test_mbedx509
    subproject_test_tfpsacrypto
    ${CMAKE_THREAD_LIBS_INIT}
)
