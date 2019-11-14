list (APPEND everest_src)
list (APPEND everest_inc)
list (APPEND everest_def)

set(everest_src
  ${CMAKE_CURRENT_SOURCE_DIR}/library/everest.c
  ${CMAKE_CURRENT_SOURCE_DIR}/library/x25519.c
  ${CMAKE_CURRENT_SOURCE_DIR}/library/Hacl_Curve25519_joined.c
)

list(APPEND everest_inc ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/include/everest ${CMAKE_CURRENT_SOURCE_DIR}/include/everest/kremlib)

execute_process(COMMAND ${PYTHON_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/../../scripts/config.py -f ${CMAKE_CURRENT_SOURCE_DIR}/../../include/mbedtls/config.h get MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED RESULT_VARIABLE result)

if(${result} EQUAL 0)

  if(INSTALL_MBEDTLS_HEADERS)

    install(DIRECTORY include/everest
      DESTINATION include
      FILE_PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
      DIRECTORY_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
      FILES_MATCHING PATTERN "*.h")

  endif(INSTALL_MBEDTLS_HEADERS)

endif()

set(thirdparty_src ${thirdparty_src} ${everest_src} PARENT_SCOPE)
set(thirdparty_inc ${thirdparty_inc} ${everest_inc} PARENT_SCOPE)
set(thirdparty_def ${thirdparty_def} ${everest_def} PARENT_SCOPE)
