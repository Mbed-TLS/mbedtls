option(INSTALL_MBEDTLS_HEADERS "Install Mbed TLS headers." ON)

# Check the MBEDTLS_CONFIG_FILE is valid if it is set
if(MBEDTLS_CONFIG_FILE)
    # we need to make sure our file paths are absolute to avoid any issues with the list command later
    if(NOT IS_ABSOLUTE "${MBEDTLS_CONFIG_FILE}")
        set(MBEDTLS_CONFIG_FILE "${CMAKE_CURRENT_SOURCE_DIR}/${MBEDTLS_CONFIG_FILE}")
        message(WARNING "**** WARNING : ${PROJECT_NAME} : Converted relative path to: ${MBEDTLS_CONFIG_FILE}")
    endif()

    if(EXISTS "${MBEDTLS_CONFIG_FILE}" AND NOT IS_DIRECTORY "${MBEDTLS_CONFIG_FILE}")
        message(STATUS "${PROJECT_NAME} : MBEDTLS_CONFIG_FILE override set to : ${MBEDTLS_CONFIG_FILE}")
    else ()
        message(FATAL_ERROR "${PROJECT_NAME} : MBEDTLS_CONFIG_FILE override invalid or inaccessible : ${MBEDTLS_CONFIG_FILE}")
    endif ()
endif ()


if(INSTALL_MBEDTLS_HEADERS)

    file(GLOB headers "mbedtls/*.h")

    # if the override is defined remove the default mbedtls_config.h and add custom header, validity checks for the override are conducted above
    if(MBEDTLS_CONFIG_FILE)
        list(REMOVE_ITEM headers "${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/mbedtls_config.h")
        list(APPEND headers ${MBEDTLS_CONFIG_FILE})
    endif ()

    install(FILES ${headers}
        DESTINATION include/mbedtls
        PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)

    file(GLOB private_headers "mbedtls/private/*.h")

    install(FILES ${private_headers}
        DESTINATION include/mbedtls/private
        PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
endif(INSTALL_MBEDTLS_HEADERS)

# Make mbedtls_config.h available in an out-of-source build. ssl-opt.sh requires it.
if (ENABLE_TESTING AND NOT ${CMAKE_CURRENT_BINARY_DIR} STREQUAL ${CMAKE_CURRENT_SOURCE_DIR})
    link_to_source(mbedtls)
endif()
