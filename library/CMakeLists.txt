option(USE_STATIC_MBEDTLS_LIBRARY "Build Mbed TLS static library." ON)
option(USE_SHARED_MBEDTLS_LIBRARY "Build Mbed TLS shared library." OFF)
option(LINK_WITH_PTHREAD "Explicitly link Mbed TLS library to pthread." OFF)
option(LINK_WITH_TRUSTED_STORAGE "Explicitly link Mbed TLS library to trusted_storage." OFF)

# Set the project root directory if it's not already defined, as may happen if
# the library folder is included directly by a parent project, without
# including the top level CMakeLists.txt.
if(NOT DEFINED MBEDTLS_DIR)
    set(MBEDTLS_DIR ${CMAKE_SOURCE_DIR})
endif()

set(TF_PSA_CRYPTO_CORE_DIR ../tf-psa-crypto/core)
set(TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR ../tf-psa-crypto/drivers/builtin/src)

set(src_crypto
    ${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/aes.c
    ${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/aesni.c
    ${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/aesce.c
    ${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/aria.c
    ${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/asn1parse.c
    ${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/asn1write.c
    ${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/base64.c
    ${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/bignum.c
    ${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/bignum_core.c
    ${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/bignum_mod.c
    ${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/bignum_mod_raw.c
    ${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/block_cipher.c
    ${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/camellia.c
    ${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/ccm.c
    ${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/chacha20.c
    ${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/chachapoly.c
    ${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/cipher.c
    ${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/cipher_wrap.c
    ${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/constant_time.c
    ${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/cmac.c
    ${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/ctr_drbg.c
    ${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/des.c
    ${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/dhm.c
    ${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/ecdh.c
    ${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/ecdsa.c
    ${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/ecjpake.c
    ${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/ecp.c
    ${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/ecp_curves.c
    ${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/ecp_curves_new.c
    ${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/entropy.c
    ${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/entropy_poll.c
    ${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/error.c
    ${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/gcm.c
    ${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/hkdf.c
    ${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/hmac_drbg.c
    ${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/lmots.c
    ${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/lms.c
    ${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/md.c
    ${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/md5.c
    ${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/memory_buffer_alloc.c
    ${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/nist_kw.c
    ${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/oid.c
    ${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/pem.c
    ${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/pk.c
    ${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/pk_ecc.c
    ${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/pk_wrap.c
    ${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/pkcs12.c
    ${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/pkcs5.c
    ${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/pkparse.c
    ${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/pkwrite.c
    ${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/platform.c
    ${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/platform_util.c
    ${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/poly1305.c
    ${TF_PSA_CRYPTO_CORE_DIR}/psa_crypto.c
    ${TF_PSA_CRYPTO_CORE_DIR}/psa_crypto_aead.c
    ${TF_PSA_CRYPTO_CORE_DIR}/psa_crypto_cipher.c
    ${TF_PSA_CRYPTO_CORE_DIR}/psa_crypto_client.c
    ${TF_PSA_CRYPTO_CORE_DIR}/psa_crypto_driver_wrappers_no_static.c
    ${TF_PSA_CRYPTO_CORE_DIR}/psa_crypto_ecp.c
    ${TF_PSA_CRYPTO_CORE_DIR}/psa_crypto_ffdh.c
    ${TF_PSA_CRYPTO_CORE_DIR}/psa_crypto_hash.c
    ${TF_PSA_CRYPTO_CORE_DIR}/psa_crypto_mac.c
    ${TF_PSA_CRYPTO_CORE_DIR}/psa_crypto_pake.c
    ${TF_PSA_CRYPTO_CORE_DIR}/psa_crypto_rsa.c
    ${TF_PSA_CRYPTO_CORE_DIR}/psa_crypto_se.c
    ${TF_PSA_CRYPTO_CORE_DIR}/psa_crypto_slot_management.c
    ${TF_PSA_CRYPTO_CORE_DIR}/psa_crypto_storage.c
    ${TF_PSA_CRYPTO_CORE_DIR}/psa_its_file.c
    ${TF_PSA_CRYPTO_CORE_DIR}/psa_util.c
    ${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/ripemd160.c
    ${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/rsa.c
    ${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/rsa_alt_helpers.c
    ${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/sha1.c
    ${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/sha256.c
    ${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/sha512.c
    ${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/sha3.c
    ${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/threading.c
    ${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/timing.c
    ${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/version.c
    ${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/version_features.c
)

set(src_x509
    pkcs7.c
    x509.c
    x509_create.c
    x509_crl.c
    x509_crt.c
    x509_csr.c
    x509write.c
    x509write_crt.c
    x509write_csr.c
)

set(src_tls
    debug.c
    mps_reader.c
    mps_trace.c
    net_sockets.c
    ssl_cache.c
    ssl_ciphersuites.c
    ssl_client.c
    ssl_cookie.c
    ssl_debug_helpers_generated.c
    ssl_msg.c
    ssl_ticket.c
    ssl_tls.c
    ssl_tls12_client.c
    ssl_tls12_server.c
    ssl_tls13_keys.c
    ssl_tls13_server.c
    ssl_tls13_client.c
    ssl_tls13_generic.c
)

if(GEN_FILES)
    find_package(Perl REQUIRED)

    file(GLOB crypto_error_headers ${CMAKE_CURRENT_SOURCE_DIR}/../tf-psa-crypto/drivers/builtin/include/mbedtls/*.h)
    file(GLOB tls_error_headers ${CMAKE_CURRENT_SOURCE_DIR}/../include/mbedtls/*.h)
    add_custom_command(
        OUTPUT
            ${CMAKE_CURRENT_BINARY_DIR}/${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/error.c
        COMMAND
            ${PERL_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/../scripts/generate_errors.pl
                ${CMAKE_CURRENT_SOURCE_DIR}/../tf-psa-crypto/drivers/builtin/include/mbedtls
                ${CMAKE_CURRENT_SOURCE_DIR}/../include/mbedtls
                ${CMAKE_CURRENT_SOURCE_DIR}/../scripts/data_files
                ${CMAKE_CURRENT_BINARY_DIR}/${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/error.c
        DEPENDS
            ${CMAKE_CURRENT_SOURCE_DIR}/../scripts/generate_errors.pl
            ${crypto_error_headers}
            ${tls_error_headers}
            ${CMAKE_CURRENT_SOURCE_DIR}/../scripts/data_files/error.fmt
    )

    add_custom_command(
        OUTPUT
            ${CMAKE_CURRENT_BINARY_DIR}/${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/version_features.c
        COMMAND
            ${PERL_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/../scripts/generate_features.pl
                ${CMAKE_CURRENT_SOURCE_DIR}/../include/mbedtls
                ${CMAKE_CURRENT_SOURCE_DIR}/../scripts/data_files
                ${CMAKE_CURRENT_BINARY_DIR}/${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/version_features.c
        DEPENDS
            ${CMAKE_CURRENT_SOURCE_DIR}/../scripts/generate_features.pl
            ${CMAKE_CURRENT_SOURCE_DIR}/../include/mbedtls/mbedtls_config.h
            ${CMAKE_CURRENT_SOURCE_DIR}/../scripts/data_files/version_features.fmt
    )

    add_custom_command(
        OUTPUT
            ${CMAKE_CURRENT_BINARY_DIR}/ssl_debug_helpers_generated.c
        COMMAND
            ${MBEDTLS_PYTHON_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/../scripts/generate_ssl_debug_helpers.py
                --mbedtls-root ${CMAKE_CURRENT_SOURCE_DIR}/..
                ${CMAKE_CURRENT_BINARY_DIR}
        DEPENDS
            ${CMAKE_CURRENT_SOURCE_DIR}/../scripts/generate_ssl_debug_helpers.py
            ${tls_error_headers}
    )

    add_custom_command(
        OUTPUT
            ${CMAKE_CURRENT_BINARY_DIR}/${TF_PSA_CRYPTO_CORE_DIR}/psa_crypto_driver_wrappers.h
            ${CMAKE_CURRENT_BINARY_DIR}/${TF_PSA_CRYPTO_CORE_DIR}/psa_crypto_driver_wrappers_no_static.c
        COMMAND
            ${MBEDTLS_PYTHON_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/../scripts/generate_driver_wrappers.py
                ${CMAKE_CURRENT_BINARY_DIR}/${TF_PSA_CRYPTO_CORE_DIR}
        DEPENDS
            ${CMAKE_CURRENT_SOURCE_DIR}/../scripts/generate_driver_wrappers.py
            ${CMAKE_CURRENT_SOURCE_DIR}/../scripts/data_files/driver_templates/psa_crypto_driver_wrappers.h.jinja
            ${CMAKE_CURRENT_SOURCE_DIR}/../scripts/data_files/driver_templates/psa_crypto_driver_wrappers_no_static.c.jinja
    )
else()
    link_to_source(${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/error.c)
    link_to_source(${TF_PSA_CRYPTO_DRIVERS_BUILTIN_SRC_DIR}/version_features.c)
    link_to_source(ssl_debug_helpers_generated.c)
    link_to_source(${TF_PSA_CRYPTO_CORE_DIR}/psa_crypto_driver_wrappers.h)
    link_to_source(${TF_PSA_CRYPTO_CORE_DIR}/psa_crypto_driver_wrappers_no_static.c)
endif()

if(CMAKE_COMPILER_IS_GNUCC)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wmissing-declarations")
endif(CMAKE_COMPILER_IS_GNUCC)

if(CMAKE_COMPILER_IS_CLANG)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wmissing-declarations -Wdocumentation -Wno-documentation-deprecated-sync -Wunreachable-code")
endif(CMAKE_COMPILER_IS_CLANG)

if(CMAKE_COMPILER_IS_MSVC)
    option(MSVC_STATIC_RUNTIME "Build the libraries with /MT compiler flag" OFF)
    if(MSVC_STATIC_RUNTIME)
        foreach(flag_var
            CMAKE_C_FLAGS CMAKE_C_FLAGS_DEBUG CMAKE_C_FLAGS_RELEASE
            CMAKE_C_FLAGS_MINSIZEREL CMAKE_C_FLAGS_RELWITHDEBINFO
            CMAKE_C_FLAGS_CHECK)
            string(REGEX REPLACE "/MD" "/MT" ${flag_var} "${${flag_var}}")
        endforeach(flag_var)
    endif()
endif()

if(WIN32)
    set(libs ${libs} ws2_32 bcrypt)
endif(WIN32)

if(CMAKE_C_COMPILER_ID MATCHES "AppleClang")
    set(CMAKE_C_ARCHIVE_CREATE   "<CMAKE_AR> Scr <TARGET> <LINK_FLAGS> <OBJECTS>")
    set(CMAKE_C_ARCHIVE_FINISH   "<CMAKE_RANLIB> -no_warning_for_no_symbols -c <TARGET>")
endif()
if(CMAKE_CXX_COMPILER_ID MATCHES "AppleClang")
    set(CMAKE_CXX_ARCHIVE_CREATE "<CMAKE_AR> Scr <TARGET> <LINK_FLAGS> <OBJECTS>")
    set(CMAKE_CXX_ARCHIVE_FINISH "<CMAKE_RANLIB> -no_warning_for_no_symbols -c <TARGET>")
endif()

if(HAIKU)
    set(libs ${libs} network)
endif(HAIKU)

if(LINK_WITH_PTHREAD)
    set(libs ${libs} ${CMAKE_THREAD_LIBS_INIT})
endif()

if(LINK_WITH_TRUSTED_STORAGE)
    set(libs ${libs} trusted_storage)
endif()

if (NOT USE_STATIC_MBEDTLS_LIBRARY AND NOT USE_SHARED_MBEDTLS_LIBRARY)
    message(FATAL_ERROR "Need to choose static or shared mbedtls build!")
endif(NOT USE_STATIC_MBEDTLS_LIBRARY AND NOT USE_SHARED_MBEDTLS_LIBRARY)

set(mbedtls_target    "${MBEDTLS_TARGET_PREFIX}mbedtls")
set(mbedx509_target   "${MBEDTLS_TARGET_PREFIX}mbedx509")
set(mbedcrypto_target "${MBEDTLS_TARGET_PREFIX}mbedcrypto")

set(mbedtls_target    ${mbedtls_target}    PARENT_SCOPE)
set(mbedx509_target   ${mbedx509_target}   PARENT_SCOPE)
set(mbedcrypto_target ${mbedcrypto_target} PARENT_SCOPE)

if (USE_STATIC_MBEDTLS_LIBRARY)
    set(mbedtls_static_target    ${mbedtls_target})
    set(mbedx509_static_target   ${mbedx509_target})
    set(mbedcrypto_static_target ${mbedcrypto_target})
endif()

set(target_libraries ${mbedcrypto_target} ${mbedx509_target} ${mbedtls_target})

if(USE_STATIC_MBEDTLS_LIBRARY AND USE_SHARED_MBEDTLS_LIBRARY)
    string(APPEND mbedtls_static_target    "_static")
    string(APPEND mbedx509_static_target   "_static")
    string(APPEND mbedcrypto_static_target "_static")

    list(APPEND target_libraries
        ${mbedcrypto_static_target}
        ${mbedx509_static_target}
        ${mbedtls_static_target})
endif()

set(p256m_target "${MBEDTLS_TARGET_PREFIX}p256m")
set(everest_target "${MBEDTLS_TARGET_PREFIX}everest")

if(USE_STATIC_MBEDTLS_LIBRARY)
    add_library(${mbedcrypto_static_target} STATIC ${src_crypto})
    set_target_properties(${mbedcrypto_static_target} PROPERTIES OUTPUT_NAME mbedcrypto)
    target_link_libraries(${mbedcrypto_static_target} PUBLIC ${libs})

    if(TARGET ${everest_target})
        target_link_libraries(${mbedcrypto_static_target} PUBLIC ${everest_target})
    endif()

    if(TARGET ${p256m_target})
        target_link_libraries(${mbedcrypto_static_target} PUBLIC ${p256m_target})
    endif()

    add_library(${mbedx509_static_target} STATIC ${src_x509})
    set_target_properties(${mbedx509_static_target} PROPERTIES OUTPUT_NAME mbedx509)
    target_link_libraries(${mbedx509_static_target} PUBLIC ${libs} ${mbedcrypto_static_target})

    add_library(${mbedtls_static_target} STATIC ${src_tls})
    set_target_properties(${mbedtls_static_target} PROPERTIES OUTPUT_NAME mbedtls)
    target_link_libraries(${mbedtls_static_target} PUBLIC ${libs} ${mbedx509_static_target})
endif(USE_STATIC_MBEDTLS_LIBRARY)

if(USE_SHARED_MBEDTLS_LIBRARY)
    set(CMAKE_LIBRARY_PATH ${CMAKE_CURRENT_BINARY_DIR})
    add_library(${mbedcrypto_target} SHARED ${src_crypto})
    set_target_properties(${mbedcrypto_target} PROPERTIES VERSION 3.6.0 SOVERSION 16)
    target_link_libraries(${mbedcrypto_target} PUBLIC ${libs})

    if(TARGET ${everest_target})
        target_link_libraries(${mbedcrypto_target} PUBLIC ${everest_target})
    endif()

    if(TARGET ${p256m_target})
        target_link_libraries(${mbedcrypto_target} PUBLIC ${p256m_target})
    endif()

    add_library(${mbedx509_target} SHARED ${src_x509})
    set_target_properties(${mbedx509_target} PROPERTIES VERSION 3.6.0 SOVERSION 7)
    target_link_libraries(${mbedx509_target} PUBLIC ${libs} ${mbedcrypto_target})

    add_library(${mbedtls_target} SHARED ${src_tls})
    set_target_properties(${mbedtls_target} PROPERTIES VERSION 3.6.0 SOVERSION 21)
    target_link_libraries(${mbedtls_target} PUBLIC ${libs} ${mbedx509_target})
endif(USE_SHARED_MBEDTLS_LIBRARY)

foreach(target IN LISTS target_libraries)
    add_library(MbedTLS::${target} ALIAS ${target})  # add_subdirectory support
    # Include public header files from /include, /tf-psa-crypto/include/ and
    # tf-psa-crypto/drivers/builtin/include/. Include private header files
    # from /library, tf-psa-crypto/core/ and tf-psa-crypto/drivers/builtin/src/.
    target_include_directories(${target}
        PUBLIC $<BUILD_INTERFACE:${MBEDTLS_DIR}/include/>
               $<BUILD_INTERFACE:${MBEDTLS_DIR}/tf-psa-crypto/include/>
               $<BUILD_INTERFACE:${MBEDTLS_DIR}/tf-psa-crypto/drivers/builtin/include/>
               $<INSTALL_INTERFACE:include/>
        PRIVATE ${MBEDTLS_DIR}/library/
                ${MBEDTLS_DIR}/tf-psa-crypto/core
                ${MBEDTLS_DIR}/tf-psa-crypto/drivers/builtin/src
                # Needed to include psa_crypto_driver_wrappers.h
                ${CMAKE_CURRENT_BINARY_DIR}/../tf-psa-crypto/core)
    # Pass-through MBEDTLS_CONFIG_FILE and MBEDTLS_USER_CONFIG_FILE
    if(MBEDTLS_CONFIG_FILE)
        target_compile_definitions(${target}
            PUBLIC MBEDTLS_CONFIG_FILE="${MBEDTLS_CONFIG_FILE}")
    endif()
    if(MBEDTLS_USER_CONFIG_FILE)
        target_compile_definitions(${target}
            PUBLIC MBEDTLS_USER_CONFIG_FILE="${MBEDTLS_USER_CONFIG_FILE}")
    endif()
    install(
        TARGETS ${target}
        EXPORT MbedTLSTargets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
endforeach(target)

set(lib_target "${MBEDTLS_TARGET_PREFIX}lib")

add_custom_target(${lib_target} DEPENDS ${mbedcrypto_target} ${mbedx509_target} ${mbedtls_target})
if(USE_STATIC_MBEDTLS_LIBRARY AND USE_SHARED_MBEDTLS_LIBRARY)
    add_dependencies(${lib_target} ${mbedcrypto_static_target} ${mbedx509_static_target} ${mbedtls_static_target})
endif()
