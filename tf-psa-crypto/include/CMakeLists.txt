option(INSTALL_PSA_CRYPTO_HEADERS "Install PSA Crypto headers." ON)

if(INSTALL_PSA_CRYPTO_HEADERS)

    file(GLOB psa_headers "psa/*.h")

    install(FILES ${psa_headers}
        DESTINATION include/psa
        PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)

endif(INSTALL_PSA_CRYPTO_HEADERS)

# Make includes available in an out-of-source build. ssl-opt.sh requires it.
if (ENABLE_TESTING AND NOT ${CMAKE_CURRENT_BINARY_DIR} STREQUAL ${CMAKE_CURRENT_SOURCE_DIR})
    link_to_source(psa)
endif()
