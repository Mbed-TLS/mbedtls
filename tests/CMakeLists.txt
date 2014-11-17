set(libs
     polarssl
)

if(USE_PKCS11_HELPER_LIBRARY)
    set(libs ${libs} pkcs11-helper)
endif(USE_PKCS11_HELPER_LIBRARY)

if(ENABLE_ZLIB_SUPPORT)
    set(libs ${libs} ${ZLIB_LIBRARIES})
endif(ENABLE_ZLIB_SUPPORT)

function(add_test_suite suite_name)
    if(ARGV1)
    set(data_name ${ARGV1})
    else()
    set(data_name ${suite_name})
    endif()

    add_custom_command(
        OUTPUT test_suite_${data_name}.c
        COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/scripts/generate_code.pl ${CMAKE_CURRENT_SOURCE_DIR}/suites test_suite_${suite_name} test_suite_${data_name}
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/scripts/generate_code.pl polarssl fct.h suites/helpers.function suites/test_suite_${suite_name}.function suites/test_suite_${data_name}.data
    )
  
    include_directories(${CMAKE_CURRENT_SOURCE_DIR})
    add_executable(test_suite_${data_name} test_suite_${data_name}.c)
    target_link_libraries(test_suite_${data_name} ${libs})
    add_test(${data_name}-suite test_suite_${data_name})
endfunction(add_test_suite)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-unused-function")

add_test_suite(aes aes.ecb)
add_test_suite(aes aes.cbc)
add_test_suite(aes aes.cfb)
add_test_suite(aes aes.rest)
add_test_suite(arc4)
add_test_suite(base64)
add_test_suite(blowfish)
add_test_suite(camellia)
add_test_suite(cipher cipher.aes)
add_test_suite(cipher cipher.blowfish)
add_test_suite(cipher cipher.camellia)
add_test_suite(cipher cipher.des)
add_test_suite(cipher cipher.null)
add_test_suite(ctr_drbg)
add_test_suite(debug)
add_test_suite(des)
add_test_suite(dhm)
add_test_suite(error)
add_test_suite(gcm gcm.encrypt_128)
add_test_suite(gcm gcm.encrypt_192)
add_test_suite(gcm gcm.encrypt_256)
add_test_suite(gcm gcm.decrypt_128)
add_test_suite(gcm gcm.decrypt_192)
add_test_suite(gcm gcm.decrypt_256)
add_test_suite(hmac_shax)
add_test_suite(md)
add_test_suite(mdx)
add_test_suite(mpi)
add_test_suite(pbkdf2)
add_test_suite(pkcs1_v21)
add_test_suite(pkcs5)
add_test_suite(shax)
add_test_suite(rsa)
add_test_suite(version)
add_test_suite(xtea)
add_test_suite(x509parse)
add_test_suite(x509write)

# Make data_files available in an out-of-source build
if (NOT ${CMAKE_CURRENT_BINARY_DIR} STREQUAL ${CMAKE_CURRENT_SOURCE_DIR})
    # Get OS dependent path to use in `execute_process`
    file(TO_NATIVE_PATH "${CMAKE_CURRENT_BINARY_DIR}/data_files" link)
    file(TO_NATIVE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/data_files" target)

    if (NOT EXISTS ${link})
        if (CMAKE_HOST_UNIX)
            set(command ln -s ${target} ${link})
        else()
            set(command cmd.exe /c mklink ${link} ${target})
        endif()

        execute_process(COMMAND ${command}
                        RESULT_VARIABLE result
                        ERROR_VARIABLE output)

        if (NOT ${result} EQUAL 0)
            message(FATAL_ERROR "Could not create symbolic link for: ${target} --> ${output}")
        endif()
    endif()
endif()

