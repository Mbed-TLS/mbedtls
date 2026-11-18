option(INSTALL_MBEDTLS_HEADERS "Install Mbed TLS headers." ON)

if(INSTALL_MBEDTLS_HEADERS)

    file(GLOB headers "mbedtls/*.h")

    if(NOT "${MBEDTLS_GENERATED_CONFIG_FILE}" STREQUAL "")
        list(REMOVE_ITEM headers
            "${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/mbedtls_config.h")
    endif()

    install(FILES ${headers}
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/mbedtls
        PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)

    if(NOT "${MBEDTLS_GENERATED_CONFIG_FILE}" STREQUAL "")
        install(FILES "${MBEDTLS_GENERATED_CONFIG_FILE}"
            DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/mbedtls
            PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
    endif()

    file(GLOB private_headers "mbedtls/private/*.h")

    install(FILES ${private_headers}
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/mbedtls/private
        PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
endif(INSTALL_MBEDTLS_HEADERS)

# Make mbedtls_config.h available in an out-of-source build. ssl-opt.sh requires it.
if (ENABLE_TESTING AND NOT ${CMAKE_CURRENT_BINARY_DIR} STREQUAL ${CMAKE_CURRENT_SOURCE_DIR})
    link_to_source(mbedtls)
endif()
