add_executable(selftest selftest.c)
target_link_libraries(selftest polarssl)

add_executable(benchmark benchmark.c)
target_link_libraries(benchmark polarssl)

add_executable(ssl_test ssl_test.c)
target_link_libraries(ssl_test polarssl)

add_executable(ssl_cert_test ssl_cert_test.c)
target_link_libraries(ssl_cert_test polarssl)

