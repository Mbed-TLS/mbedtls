set(libs
    ${mbedtls_target}
)

set(executables_libs
    selftest
    udp_proxy
)

set(executables_mbedcrypto
    benchmark
    query_compile_time_config
    zeroize
)

if(TEST_CPP)
    list(APPEND executables_mbedcrypto cpp_dummy_build)
endif()

foreach(exe IN LISTS executables_libs executables_mbedcrypto)
    set(extra_sources "")
    if(exe STREQUAL "query_compile_time_config")
        list(APPEND extra_sources
            ${CMAKE_CURRENT_SOURCE_DIR}/query_config.c)
    endif()
    add_executable(${exe} ${exe}.c $<TARGET_OBJECTS:mbedtls_test>
        ${extra_sources})
    target_include_directories(${exe} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../tests/include)

    # This emulates "if ( ... IN_LIST ... )" which becomes available in CMake 3.3
    list(FIND executables_libs ${exe} exe_index)
    if (${exe_index} GREATER -1)
        target_link_libraries(${exe} ${libs})
    else()
        target_link_libraries(${exe} ${mbedcrypto_target})
    endif()
endforeach()

install(TARGETS ${executables_libs} ${executables_mbedcrypto}
        DESTINATION "bin"
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
