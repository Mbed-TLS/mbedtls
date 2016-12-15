set(libs
    mbedtls
)

if(MSVC)
    set(libs ${libs} bcrypt)
endif()

add_executable(dh_client dh_client.c)
target_link_libraries(dh_client ${libs})

add_executable(dh_genprime dh_genprime.c)
target_link_libraries(dh_genprime ${libs})

add_executable(dh_server dh_server.c)
target_link_libraries(dh_server ${libs})

add_executable(ecdh_curve25519 ecdh_curve25519.c)
target_link_libraries(ecdh_curve25519 ${libs})

add_executable(ecdsa ecdsa.c)
target_link_libraries(ecdsa ${libs})

add_executable(gen_key gen_key.c)
target_link_libraries(gen_key ${libs})

add_executable(key_app key_app.c)
target_link_libraries(key_app ${libs})

add_executable(key_app_writer key_app_writer.c)
target_link_libraries(key_app_writer ${libs})

add_executable(mpi_demo mpi_demo.c)
target_link_libraries(mpi_demo ${libs})

add_executable(rsa_genkey rsa_genkey.c)
target_link_libraries(rsa_genkey ${libs})

add_executable(rsa_sign rsa_sign.c)
target_link_libraries(rsa_sign ${libs})

add_executable(rsa_verify rsa_verify.c)
target_link_libraries(rsa_verify ${libs})

add_executable(rsa_sign_pss rsa_sign_pss.c)
target_link_libraries(rsa_sign_pss ${libs})

add_executable(rsa_verify_pss rsa_verify_pss.c)
target_link_libraries(rsa_verify_pss ${libs})

add_executable(rsa_encrypt rsa_encrypt.c)
target_link_libraries(rsa_encrypt ${libs})

add_executable(rsa_decrypt rsa_decrypt.c)
target_link_libraries(rsa_decrypt ${libs})

add_executable(pk_sign pk_sign.c)
target_link_libraries(pk_sign ${libs})

add_executable(pk_verify pk_verify.c)
target_link_libraries(pk_verify ${libs})

add_executable(pk_encrypt pk_encrypt.c)
target_link_libraries(pk_encrypt ${libs})

add_executable(pk_decrypt pk_decrypt.c)
target_link_libraries(pk_decrypt ${libs})

install(TARGETS dh_client dh_genprime dh_server key_app mpi_demo rsa_genkey rsa_sign rsa_verify rsa_encrypt rsa_decrypt pk_encrypt pk_decrypt pk_sign pk_verify gen_key
        DESTINATION "bin"
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
