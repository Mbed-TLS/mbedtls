include_directories(include include/everest include/everest/kremlib)

set(src_everest
  ${CMAKE_CURRENT_SOURCE_DIR}/library/everest.c
  ${CMAKE_CURRENT_SOURCE_DIR}/library/Hacl_Curve25519.c
  ${CMAKE_CURRENT_SOURCE_DIR}/library/x25519.c
  ${CMAKE_CURRENT_SOURCE_DIR}/library/kremlib/FStar_UInt64_FStar_UInt32_FStar_UInt16_FStar_UInt8.c
  PARENT_SCOPE
)

