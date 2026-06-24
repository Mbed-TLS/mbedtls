list(APPEND dispatch_src_files
    "${CMAKE_CURRENT_SOURCE_DIR}/custom_dispatch.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/psa_crypto_driver_wrappers_no_static.c"
)

set(tf_psa_crypto_objlib "dispatch")
include(${PROJECT_SOURCE_DIR}/objlib.cmake)
