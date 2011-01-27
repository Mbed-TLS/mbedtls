add_executable(gen_random gen_random.c)
target_link_libraries(gen_random polarssl)

INSTALL(TARGETS gen_random
        DESTINATION "bin"
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
