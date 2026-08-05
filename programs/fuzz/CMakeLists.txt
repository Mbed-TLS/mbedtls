set(libs
    ${mbedtls_target}
    ${CMAKE_THREAD_LIBS_INIT}
)

find_library(FUZZINGENGINE_LIB FuzzingEngine)
if(FUZZINGENGINE_LIB)
    project(fuzz CXX)
endif()

set(executables
    fuzz_client
    fuzz_dtlsclient
    fuzz_dtlsserver
    fuzz_server
    fuzz_x509crl
    fuzz_x509crt
    fuzz_x509csr
    fuzz_pkcs7
    fuzz_ssl_session
    fuzz_ssl_context
    fuzz_dtls_record
    fuzz_x509_verify
)
add_dependencies(${programs_target} ${executables})

foreach(exe IN LISTS executables)

    set(exe_sources
        ${exe}.c
        $<TARGET_OBJECTS:mbedtls_test_helpers>
        $<TARGET_OBJECTS:mbedtls_test>
        ${MBEDTLS_DIR}/tf-psa-crypto/programs/fuzz/fuzz_common.c)
    if(NOT FUZZINGENGINE_LIB)
        list(APPEND exe_sources ${MBEDTLS_DIR}/tf-psa-crypto/programs/fuzz/fuzz_onefile.c)
    endif()

    add_executable(${exe} ${exe_sources})
    set_base_compile_options(${exe})
    target_include_directories(${exe} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../framework/tests/include
                                              ${CMAKE_CURRENT_SOURCE_DIR}/../../tf-psa-crypto/programs/fuzz/
                                              ${CMAKE_CURRENT_SOURCE_DIR}/../../tests/include
                                              ${MBEDTLS_DIR}/library
                                              ${TF_PSA_CRYPTO_PRIVATE_INCLUDE_DIRS})

    if (NOT FUZZINGENGINE_LIB)
        target_link_libraries(${exe} ${libs})
    else()
        target_link_libraries(${exe} ${libs} FuzzingEngine)
        SET_TARGET_PROPERTIES(${exe} PROPERTIES LINKER_LANGUAGE CXX)
    endif()

endforeach()
