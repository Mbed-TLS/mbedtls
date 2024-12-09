set(programs_target "${TF_PSA_CRYPTO_TARGET_PREFIX}tfpsacrypto-programs")
add_custom_target(${programs_target})

add_subdirectory(psa)
