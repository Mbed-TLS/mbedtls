cmake_minimum_required(VERSION 2.6)
# 定义工程名称
project("hmac-test")

# 定义依赖动态链接库
set(libs
    mbedtls
 	mbedcrypto 
	mbedx509
)

set(targets
    hmac-test
)

add_executable(hmac-test hmac-test.c)
target_link_libraries(hmac-test ${libs})

