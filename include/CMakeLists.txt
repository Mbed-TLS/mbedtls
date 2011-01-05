FILE(GLOB headers "polarssl/*.h")

INSTALL(FILES ${headers}
        DESTINATION include/polarssl
        PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
