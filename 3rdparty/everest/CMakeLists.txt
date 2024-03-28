set(everest_target "${MBEDTLS_TARGET_PREFIX}everest")

add_library(${everest_target}
  library/everest.c
  library/x25519.c
  library/Hacl_Curve25519_joined.c)

target_include_directories(${everest_target}
  PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
         $<BUILD_INTERFACE:${MBEDTLS_DIR}/include>
         $<INSTALL_INTERFACE:include>
  PRIVATE include/everest
          include/everest/kremlib
          ${MBEDTLS_DIR}/library/)

# Pass-through MBEDTLS_CONFIG_FILE and MBEDTLS_USER_CONFIG_FILE
# This must be duplicated from library/CMakeLists.txt because
# everest is not directly linked against any mbedtls targets
# so does not inherit the compile definitions.
if(MBEDTLS_CONFIG_FILE)
    target_compile_definitions(${everest_target}
        PUBLIC MBEDTLS_CONFIG_FILE="${MBEDTLS_CONFIG_FILE}")
endif()
if(MBEDTLS_USER_CONFIG_FILE)
    target_compile_definitions(${everest_target}
        PUBLIC MBEDTLS_USER_CONFIG_FILE="${MBEDTLS_USER_CONFIG_FILE}")
endif()

if(INSTALL_MBEDTLS_HEADERS)
  install(DIRECTORY include/everest
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING PATTERN "*.h")

endif(INSTALL_MBEDTLS_HEADERS)

install(TARGETS ${everest_target}
  EXPORT MbedTLSTargets
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)
