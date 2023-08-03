execute_process(COMMAND ${MBEDTLS_PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/../scripts/config.py -f ${CMAKE_CURRENT_SOURCE_DIR}/../include/mbedtls/mbedtls_config.h get MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED RESULT_VARIABLE everest_result)
execute_process(COMMAND ${MBEDTLS_PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/../scripts/config.py -f ${CMAKE_CURRENT_SOURCE_DIR}/../include/mbedtls/mbedtls_config.h get MBEDTLS_P256M_EXAMPLE_DRIVER_ENABLED RESULT_VARIABLE p256m_result)

if(${everest_result} EQUAL 0)
    add_subdirectory(everest)
endif()

if(${p256m_result} EQUAL 0)
    add_subdirectory(p256-m)
endif()
