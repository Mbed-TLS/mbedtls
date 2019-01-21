list (APPEND everest_src)
list (APPEND everest_inc)
list (APPEND everest_def)

execute_process(COMMAND ${PERL_EXECUTABLE} ../scripts/config.pl -f ../include/mbedtls/config.h get MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED RESULT_VARIABLE result)

if(${result} EQUAL 0)
  set(everest_src
    ${CMAKE_CURRENT_SOURCE_DIR}/library/everest.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/x25519.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/kremlib/FStar_UInt64_FStar_UInt32_FStar_UInt16_FStar_UInt8.c
  )

  if (${CMAKE_LIBRARY_ARCHITECTURE} STREQUAL "x86_64-linux-gnu")
  list(APPEND everest_src ${CMAKE_CURRENT_SOURCE_DIR}/library/Hacl_Curve25519.c)
  else()
  list(APPEND everest_def -DKRML_VERIFIED_UINT128)
  list(APPEND everest_src
    ${CMAKE_CURRENT_SOURCE_DIR}/library/legacy/Hacl_Curve25519.c
    ${CMAKE_CURRENT_SOURCE_DIR}/library/kremlib/FStar_UInt128_extracted.c
  )
  endif()

  list(APPEND everest_inc ${CMAKE_CURRENT_SOURCE_DIR}/../../include ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/include/everest ${CMAKE_CURRENT_SOURCE_DIR}/include/everest/kremlib)

  if(INSTALL_MBEDTLS_HEADERS)

      file(GLOB_RECURSE headers "${CMAKE_CURRENT_SOURCE_DIR}/include/everest/*.h")

      install(FILES ${headers}
          DESTINATION include/everest
          PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)

  endif(INSTALL_MBEDTLS_HEADERS)

endif()

set(thirdparty_src ${thirdparty_src} ${everest_src} PARENT_SCOPE)
set(thirdparty_inc ${thirdparty_inc} ${everest_inc} PARENT_SCOPE)
set(thirdparty_def ${thirdparty_def} ${everest_def} PARENT_SCOPE)
