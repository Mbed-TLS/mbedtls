function(add_test_suite suite_name)
    add_custom_command(
        OUTPUT test_suite_${suite_name}.c
        COMMAND scripts/generate_code.pl suites test_suite_${suite_name}
        DEPENDS scripts/generate_code.pl polarssl fct.h suites/helpers.function suites/test_suite_${suite_name}.function suites/test_suite_${suite_name}.data
)

    add_executable(test_suite_${suite_name} test_suite_${suite_name}.c)
    target_link_libraries(test_suite_${suite_name} polarssl)
    add_test(${suite_name}-suite test_suite_${suite_name})
endfunction(add_test_suite)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-unused-function -Wno-unused-value")

add_test_suite(mpi)
add_test_suite(base64)
add_test_suite(arc4)
add_test_suite(mdx)
add_test_suite(shax)
add_test_suite(hmac_shax)
add_test_suite(aes)
add_test_suite(camellia)
add_test_suite(des)
add_test_suite(rsa)
add_test_suite(xtea)
add_test_suite(dhm)
add_test_suite(x509parse)
add_test_suite(debug)
