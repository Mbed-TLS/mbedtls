add_library(polarssl STATIC
     base64.c rsa.c timing.c havege.c
     md5.c
     ssl_cli.c 
     bignum.c    debug.c              sha1.c  x509parse.c
     aes.c        net.c      ssl_srv.c 
     camellia.c  des.c                md2.c             sha2.c   xtea.c
     arc4.c
     padlock.c
     ssl_tls.c
     certs.c
     dhm.c
     md4.c
     sha4.c
)
