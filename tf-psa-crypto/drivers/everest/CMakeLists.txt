set(everest_target "${TF_PSA_CRYPTO_TARGET_PREFIX}everest")

add_library(${everest_target}
  library/everest.c
  library/x25519.c
  library/Hacl_Curve25519_joined.c)

set_base_compile_options(${everest_target})
target_include_directories(${everest_target}
  PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
         $<BUILD_INTERFACE:${TF_PSA_CRYPTO_DIR}/include>
         $<BUILD_INTERFACE:${TF_PSA_CRYPTO_DIR}/drivers/builtin/include>
         $<INSTALL_INTERFACE:include>
  PRIVATE include/everest
          include/everest/kremlib
          ${TF_PSA_CRYPTO_DIR}/core)
set_config_files_compile_definitions(${everest_target})

if(INSTALL_TF_PSA_CRYPTO_HEADERS)

  install(DIRECTORY include/everest
    DESTINATION include
    FILE_PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
    DIRECTORY_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
    FILES_MATCHING PATTERN "*.h")

endif(INSTALL_TF_PSA_CRYPTO_HEADERS)

install(TARGETS ${everest_target}
  EXPORT MbedTLSTargets
  DESTINATION ${CMAKE_INSTALL_LIBDIR}
  PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)

install(TARGETS ${everest_target}
  EXPORT TF-PSA-CryptoTargets
  DESTINATION ${CMAKE_INSTALL_LIBDIR}
  PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
