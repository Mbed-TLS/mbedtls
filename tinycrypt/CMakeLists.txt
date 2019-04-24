set(src_tinycrypt
    ecc_dh.c
    ecc_dsa.c
    ecc.c
)

add_library(tinycrypt STATIC ${src_tinycrypt})
