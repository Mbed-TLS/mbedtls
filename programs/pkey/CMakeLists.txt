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
