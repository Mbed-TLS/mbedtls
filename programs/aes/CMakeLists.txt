add_executable(aescrypt2 aescrypt2.c)
target_link_libraries(aescrypt2 polarssl)

INSTALL(TARGETS aescrypt2
        DESTINATION "bin"
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
