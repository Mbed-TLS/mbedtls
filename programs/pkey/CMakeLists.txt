add_executable(dh_client dh_client.c)
target_link_libraries(dh_client polarssl)

add_executable(dh_genprime dh_genprime.c)
target_link_libraries(dh_genprime polarssl)

add_executable(dh_server dh_server.c)
target_link_libraries(dh_server polarssl)

add_executable(mpi_demo mpi_demo.c)
target_link_libraries(mpi_demo polarssl)

add_executable(rsa_genkey rsa_genkey.c)
target_link_libraries(rsa_genkey polarssl)

add_executable(rsa_sign rsa_sign.c)
target_link_libraries(rsa_sign polarssl)

add_executable(rsa_verify rsa_verify.c)
target_link_libraries(rsa_verify polarssl)

add_executable(rsa_sign_pss rsa_sign_pss.c)
target_link_libraries(rsa_sign_pss polarssl)

add_executable(rsa_verify_pss rsa_verify_pss.c)
target_link_libraries(rsa_verify_pss polarssl)

INSTALL(TARGETS dh_client dh_genprime dh_server mpi_demo rsa_genkey rsa_sign rsa_verify
        DESTINATION "bin"
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
