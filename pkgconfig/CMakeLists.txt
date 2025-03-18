if(NOT DISABLE_PACKAGE_CONFIG_AND_INSTALL)
  include(JoinPaths.cmake)
  join_paths(PKGCONFIG_INCLUDEDIR "\${prefix}" "${CMAKE_INSTALL_INCLUDEDIR}")
  join_paths(PKGCONFIG_LIBDIR "\${prefix}" "${CMAKE_INSTALL_LIBDIR}")

  #define these manually since minimum CMAKE version is not 3.9 for DESCRIPTION and 3.12 for HOMEPAGE_URL usage in project() below.
  # Prefix with something that won't clash with newer versions of CMAKE.
  set(PKGCONFIG_PROJECT_DESCRIPTION "Mbed TLS is a C library that implements cryptographic primitives, X.509 certificate manipulation and the SSL/TLS and DTLS protocols. Its small code footprint makes it suitable for embedded systems.")
  set(PKGCONFIG_PROJECT_HOMEPAGE_URL "https://www.trustedfirmware.org/projects/mbed-tls/")

  configure_file(mbedcrypto.pc.in mbedcrypto${VERSION_SUFFIX}.pc @ONLY)
    install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/mbedcrypto${VERSION_SUFFIX}.pc
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

  configure_file(mbedtls.pc.in mbedtls${VERSION_SUFFIX}.pc @ONLY)
    install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/mbedtls${VERSION_SUFFIX}.pc
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

  configure_file(mbedx509.pc.in mbedx509${VERSION_SUFFIX}.pc @ONLY)
    install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/mbedx509${VERSION_SUFFIX}.pc
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
endif()
