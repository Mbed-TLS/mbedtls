# To guarantee that the handhake messages are large enough and need to be split
# into fragments, the tests require certificate authentication. The party in control
# of the fragmentation operations is OpenSSL and will always use server5.crt (548 Bytes).
requires_certificate_authentication
run_test    "Handshake defragmentation on client (no fragmentation, for reference)" \
            "$O_NEXT_SRV" \
            "$P_CLI debug_level=4 " \
            0 \
            -C "reassembled record" \
            -C "waiting for more fragments"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_certificate_authentication
run_test    "Handshake defragmentation on client: len=512, TLS 1.3" \
            "$O_NEXT_SRV -tls1_3 -split_send_frag 512 " \
            "$P_CLI debug_level=4 " \
            0 \
            -c "reassembled record" \
            -c "handshake fragment: 0 \\.\\. 512 of [0-9]\\+ msglen 512" \
            -c "waiting for more fragments (512 of [0-9]\\+"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_2
requires_certificate_authentication
run_test    "Handshake defragmentation on client: len=512, TLS 1.2" \
            "$O_NEXT_SRV -tls1_2 -split_send_frag 512 " \
            "$P_CLI debug_level=4 " \
            0 \
            -c "reassembled record" \
            -c "handshake fragment: 0 \\.\\. 512 of [0-9]\\+ msglen 512" \
            -c "waiting for more fragments (512 of [0-9]\\+"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_certificate_authentication
run_test    "Handshake defragmentation on client: len=513, TLS 1.3" \
            "$O_NEXT_SRV -tls1_3 -split_send_frag 513 " \
            "$P_CLI debug_level=4 " \
            0 \
            -c "reassembled record" \
            -c "handshake fragment: 0 \\.\\. 513 of [0-9]\\+ msglen 513" \
            -c "waiting for more fragments (513 of [0-9]\\+"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_2
requires_certificate_authentication
run_test    "Handshake defragmentation on client: len=513, TLS 1.2" \
            "$O_NEXT_SRV -tls1_2 -split_send_frag 513 " \
            "$P_CLI debug_level=4 " \
            0 \
            -c "reassembled record" \
            -c "handshake fragment: 0 \\.\\. 513 of [0-9]\\+ msglen 513" \
            -c "waiting for more fragments (513 of [0-9]\\+"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_certificate_authentication
run_test    "Handshake defragmentation on client: len=256, TLS 1.3" \
            "$O_NEXT_SRV -tls1_3 -split_send_frag 256 " \
            "$P_CLI debug_level=4 " \
            0 \
            -c "reassembled record" \
            -c "handshake fragment: 0 \\.\\. 256 of [0-9]\\+ msglen 256" \
            -c "waiting for more fragments (256 of [0-9]\\+"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_2
requires_certificate_authentication
run_test    "Handshake defragmentation on client: len=256, TLS 1.2" \
            "$O_NEXT_SRV -tls1_2 -split_send_frag 256 " \
            "$P_CLI debug_level=4 " \
            0 \
            -c "reassembled record" \
            -c "handshake fragment: 0 \\.\\. 256 of [0-9]\\+ msglen 256" \
            -c "waiting for more fragments (256 of [0-9]\\+"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_certificate_authentication
run_test    "Handshake defragmentation on client: len=128, TLS 1.3" \
            "$O_NEXT_SRV -tls1_3 -split_send_frag 128 " \
            "$P_CLI debug_level=4 " \
            0 \
            -c "reassembled record" \
            -c "handshake fragment: 0 \\.\\. 128 of [0-9]\\+ msglen 128" \
            -c "waiting for more fragments (128"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_2
requires_certificate_authentication
run_test    "Handshake defragmentation on client: len=128, TLS 1.2" \
            "$O_NEXT_SRV -tls1_2 -split_send_frag 128 " \
            "$P_CLI debug_level=4 " \
            0 \
            -c "reassembled record" \
            -c "handshake fragment: 0 \\.\\. 128 of [0-9]\\+ msglen 128" \
            -c "waiting for more fragments (128"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_certificate_authentication
run_test    "Handshake defragmentation on client: len=64, TLS 1.3" \
            "$O_NEXT_SRV -tls1_3 -split_send_frag 64 " \
            "$P_CLI debug_level=4 " \
            0 \
            -c "reassembled record" \
            -c "handshake fragment: 0 \\.\\. 64 of [0-9]\\+ msglen 64" \
            -c "waiting for more fragments (64"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_2
requires_certificate_authentication
run_test    "Handshake defragmentation on client: len=64, TLS 1.2" \
            "$O_NEXT_SRV -tls1_2 -split_send_frag 64 " \
            "$P_CLI debug_level=4 " \
            0 \
            -c "reassembled record" \
            -c "handshake fragment: 0 \\.\\. 64 of [0-9]\\+ msglen 64" \
            -c "waiting for more fragments (64"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_certificate_authentication
run_test    "Handshake defragmentation on client: len=36, TLS 1.3" \
            "$O_NEXT_SRV -tls1_3 -split_send_frag 36 " \
            "$P_CLI debug_level=4 " \
            0 \
            -c "reassembled record" \
            -c "handshake fragment: 0 \\.\\. 36 of [0-9]\\+ msglen 36" \
            -c "waiting for more fragments (36"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_2
requires_certificate_authentication
run_test    "Handshake defragmentation on client: len=36, TLS 1.2" \
            "$O_NEXT_SRV -tls1_2 -split_send_frag 36 " \
            "$P_CLI debug_level=4 " \
            0 \
            -c "reassembled record" \
            -c "handshake fragment: 0 \\.\\. 36 of [0-9]\\+ msglen 36" \
            -c "waiting for more fragments (36"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_certificate_authentication
run_test    "Handshake defragmentation on client: len=32, TLS 1.3" \
            "$O_NEXT_SRV -tls1_3 -split_send_frag 32 " \
            "$P_CLI debug_level=4 " \
            0 \
            -c "reassembled record" \
            -c "handshake fragment: 0 \\.\\. 32 of [0-9]\\+ msglen 32" \
            -c "waiting for more fragments (32"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_2
requires_certificate_authentication
run_test    "Handshake defragmentation on client: len=32, TLS 1.2" \
            "$O_NEXT_SRV -tls1_2 -split_send_frag 32 " \
            "$P_CLI debug_level=4 " \
            0 \
            -c "reassembled record" \
            -c "handshake fragment: 0 \\.\\. 32 of [0-9]\\+ msglen 32" \
            -c "waiting for more fragments (32"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_certificate_authentication
run_test    "Handshake defragmentation on client: len=16, TLS 1.3" \
            "$O_NEXT_SRV -tls1_3 -split_send_frag 16 " \
            "$P_CLI debug_level=4 " \
            0 \
            -c "reassembled record" \
            -c "handshake fragment: 0 \\.\\. 16 of [0-9]\\+ msglen 16" \
            -c "waiting for more fragments (16"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_2
requires_certificate_authentication
run_test    "Handshake defragmentation on client: len=16, TLS 1.2" \
            "$O_NEXT_SRV -tls1_2 -split_send_frag 16 " \
            "$P_CLI debug_level=4 " \
            0 \
            -c "reassembled record" \
            -c "handshake fragment: 0 \\.\\. 16 of [0-9]\\+ msglen 16" \
            -c "waiting for more fragments (16"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_certificate_authentication
run_test    "Handshake defragmentation on client: len=13, TLS 1.3" \
            "$O_NEXT_SRV -tls1_3 -split_send_frag 13 " \
            "$P_CLI debug_level=4 " \
            0 \
            -c "reassembled record" \
            -c "handshake fragment: 0 \\.\\. 13 of [0-9]\\+ msglen 13" \
            -c "waiting for more fragments (13"

skip_next_test
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_2
requires_certificate_authentication
run_test    "Handshake defragmentation on client: len=13, TLS 1.2" \
            "$O_NEXT_SRV -tls1_2 -split_send_frag 13 " \
            "$P_CLI debug_level=4 " \
            0 \
            -c "reassembled record" \
            -c "handshake fragment: 0 \\.\\. 13 of [0-9]\\+ msglen 13" \
            -c "waiting for more fragments (13"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_certificate_authentication
run_test    "Handshake defragmentation on client: len=5, TLS 1.3" \
            "$O_NEXT_SRV -tls1_3 -split_send_frag 5 " \
            "$P_CLI debug_level=4 " \
            0 \
            -c "reassembled record" \
            -c "handshake fragment: 0 \\.\\. 5 of [0-9]\\+ msglen 5" \
            -c "waiting for more fragments (5"

skip_next_test
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_2
requires_certificate_authentication
run_test    "Handshake defragmentation on client: len=5, TLS 1.2" \
            "$O_NEXT_SRV -tls1_2 -split_send_frag 5 " \
            "$P_CLI debug_level=4 " \
            0 \
            -c "reassembled record" \
            -c "handshake fragment: 0 \\.\\. 5 of [0-9]\\+ msglen 5" \
            -c "waiting for more fragments (5"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_certificate_authentication
run_test    "Handshake defragmentation on client: len=4, TLS 1.3" \
            "$O_NEXT_SRV -tls1_3 -split_send_frag 4 " \
            "$P_CLI debug_level=4 " \
            0 \
            -c "reassembled record" \
            -c "handshake fragment: 0 \\.\\. 4 of [0-9]\\+ msglen 4" \
            -c "waiting for more fragments (4"

skip_next_test
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_2
requires_certificate_authentication
run_test    "Handshake defragmentation on client: len=4, TLS 1.2" \
            "$O_NEXT_SRV -tls1_2 -split_send_frag 4 " \
            "$P_CLI debug_level=4 " \
            0 \
            -c "reassembled record" \
            -c "handshake fragment: 0 \\.\\. 4 of [0-9]\\+ msglen 4" \
            -c "waiting for more fragments (4"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_certificate_authentication
run_test    "Handshake defragmentation on client: len=3, TLS 1.3" \
            "$O_NEXT_SRV -tls1_3 -split_send_frag 3 " \
            "$P_CLI debug_level=4 " \
            1 \
            -c "=> ssl_tls13_process_server_hello" \
            -c "handshake message too short: 3" \
            -c "SSL - An invalid SSL record was received"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_2
run_test    "Handshake defragmentation on client: len=3, TLS 1.2" \
            "$O_NEXT_SRV -tls1_2 -split_send_frag 3 " \
            "$P_CLI debug_level=4 " \
            1 \
            -c "handshake message too short: 3" \
            -c "SSL - An invalid SSL record was received"

requires_certificate_authentication
run_test    "Handshake defragmentation on server (no fragmentation, for reference)." \
            "$P_SRV debug_level=4 auth_mode=required" \
            "$O_NEXT_CLI -cert $DATA_FILES_PATH/server5.crt -key $DATA_FILES_PATH/server5.key" \
            0 \
            -S "reassembled record" \
            -S "waiting for more fragments"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_certificate_authentication
run_test    "Handshake defragmentation on server: len=512, TLS 1.3" \
            "$P_SRV debug_level=4 auth_mode=required" \
            "$O_NEXT_CLI -tls1_3 -split_send_frag 512 -cert $DATA_FILES_PATH/server5.crt -key $DATA_FILES_PATH/server5.key" \
            0 \
            -s "reassembled record" \
            -s "handshake fragment: 0 \\.\\. 512 of [0-9]\\+ msglen 512" \
            -s "waiting for more fragments (512"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_2
requires_certificate_authentication
run_test    "Handshake defragmentation on server: len=512, TLS 1.2" \
            "$P_SRV debug_level=4 auth_mode=required" \
            "$O_NEXT_CLI -tls1_2 -split_send_frag 512 -cert $DATA_FILES_PATH/server5.crt -key $DATA_FILES_PATH/server5.key" \
            0 \
            -s "reassembled record" \
            -s "handshake fragment: 0 \\.\\. 512 of [0-9]\\+ msglen 512" \
            -s "waiting for more fragments (512"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_certificate_authentication
run_test    "Handshake defragmentation on server: len=513, TLS 1.3" \
            "$P_SRV debug_level=4 auth_mode=required" \
            "$O_NEXT_CLI -tls1_3 -split_send_frag 513 -cert $DATA_FILES_PATH/server5.crt -key $DATA_FILES_PATH/server5.key" \
            0 \
            -s "reassembled record" \
            -s "handshake fragment: 0 \\.\\. 513 of [0-9]\\+ msglen 513" \
            -s "waiting for more fragments (513"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_2
requires_certificate_authentication
run_test    "Handshake defragmentation on server: len=513, TLS 1.2" \
            "$P_SRV debug_level=4 auth_mode=required" \
            "$O_NEXT_CLI -tls1_2 -split_send_frag 513 -cert $DATA_FILES_PATH/server5.crt -key $DATA_FILES_PATH/server5.key" \
            0 \
            -s "reassembled record" \
            -s "handshake fragment: 0 \\.\\. 513 of [0-9]\\+ msglen 513" \
            -s "waiting for more fragments (513"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_certificate_authentication
run_test    "Handshake defragmentation on server: len=256, TLS 1.3" \
            "$P_SRV debug_level=4 auth_mode=required" \
            "$O_NEXT_CLI -tls1_3 -split_send_frag 256 -cert $DATA_FILES_PATH/server5.crt -key $DATA_FILES_PATH/server5.key" \
            0 \
            -s "reassembled record" \
            -s "handshake fragment: 0 \\.\\. 256 of [0-9]\\+ msglen 256" \
            -s "waiting for more fragments (256"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_2
requires_certificate_authentication
run_test    "Handshake defragmentation on server: len=256, TLS 1.2" \
            "$P_SRV debug_level=4 auth_mode=required" \
            "$O_NEXT_CLI -tls1_2 -split_send_frag 256 -cert $DATA_FILES_PATH/server5.crt -key $DATA_FILES_PATH/server5.key" \
            0 \
            -s "reassembled record" \
            -s "handshake fragment: 0 \\.\\. 256 of [0-9]\\+ msglen 256" \
            -s "waiting for more fragments (256"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_certificate_authentication
run_test    "Handshake defragmentation on server: len=128, TLS 1.3" \
            "$P_SRV debug_level=4 auth_mode=required" \
            "$O_NEXT_CLI -tls1_3 -split_send_frag 128 -cert $DATA_FILES_PATH/server5.crt -key $DATA_FILES_PATH/server5.key" \
            0 \
            -s "reassembled record" \
            -s "handshake fragment: 0 \\.\\. 128 of [0-9]\\+ msglen 128" \
            -s "waiting for more fragments (128"

# Server-side ClientHello defragmentationis only supported for MBEDTLS_SSL_PROTO_TLS1_3. For TLS 1.2 testing
# the server should suport both protocols and downgrade to client-requested TL1.2 after proccessing the ClientHello.
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_2
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_certificate_authentication
run_test    "Handshake defragmentation on server: len=128, TLS 1.2  TLS 1.3 ClientHello -> 1.2 Handshake" \
            "$P_SRV debug_level=4 auth_mode=required" \
            "$O_NEXT_CLI -tls1_2 -split_send_frag 128 -cert $DATA_FILES_PATH/server5.crt -key $DATA_FILES_PATH/server5.key" \
            0 \
            -s "reassembled record" \
            -s "handshake fragment: 0 \\.\\. 128 of [0-9]\\+ msglen 128" \
            -s "waiting for more fragments (128"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_certificate_authentication
run_test    "Handshake defragmentation on server: len=64, TLS 1.3" \
            "$P_SRV debug_level=4 auth_mode=required" \
            "$O_NEXT_CLI -tls1_3 -split_send_frag 64 -cert $DATA_FILES_PATH/server5.crt -key $DATA_FILES_PATH/server5.key" \
            0 \
            -s "reassembled record" \
            -s "handshake fragment: 0 \\.\\. 64 of [0-9]\\+ msglen 64" \
            -s "waiting for more fragments (64"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_2
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_certificate_authentication
run_test    "Handshake defragmentation on server: len=64, TLS 1.2  TLS 1.3 ClientHello -> 1.2 Handshake" \
            "$P_SRV debug_level=4 auth_mode=required" \
            "$O_NEXT_CLI -tls1_2 -split_send_frag 64 -cert $DATA_FILES_PATH/server5.crt -key $DATA_FILES_PATH/server5.key" \
            0 \
            -s "reassembled record" \
            -s "handshake fragment: 0 \\.\\. 64 of [0-9]\\+ msglen 64" \
            -s "waiting for more fragments (64"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_certificate_authentication
run_test    "Handshake defragmentation on server: len=36, TLS 1.3" \
            "$P_SRV debug_level=4 auth_mode=required" \
            "$O_NEXT_CLI -tls1_3 -split_send_frag 36 -cert $DATA_FILES_PATH/server5.crt -key $DATA_FILES_PATH/server5.key" \
            0 \
            -s "reassembled record" \
            -s "handshake fragment: 0 \\.\\. 36 of [0-9]\\+ msglen 36" \
            -s "waiting for more fragments (36"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_2
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_certificate_authentication
run_test    "Handshake defragmentation on server: len=36, TLS 1.2  TLS 1.3 ClientHello -> 1.2 Handshake" \
            "$P_SRV debug_level=4 auth_mode=required" \
            "$O_NEXT_CLI -tls1_2 -split_send_frag 36 -cert $DATA_FILES_PATH/server5.crt -key $DATA_FILES_PATH/server5.key" \
            0 \
            -s "reassembled record" \
            -s "handshake fragment: 0 \\.\\. 36 of [0-9]\\+ msglen 36" \
            -s "waiting for more fragments (36"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_certificate_authentication
run_test    "Handshake defragmentation on server: len=32, TLS 1.3" \
            "$P_SRV debug_level=4 auth_mode=required" \
            "$O_NEXT_CLI -tls1_3 -split_send_frag 32 -cert $DATA_FILES_PATH/server5.crt -key $DATA_FILES_PATH/server5.key" \
            0 \
            -s "reassembled record" \
            -s "handshake fragment: 0 \\.\\. 32 of [0-9]\\+ msglen 32" \
            -s "waiting for more fragments (32"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_2
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_certificate_authentication
run_test    "Handshake defragmentation on server: len=32, TLS 1.2  TLS 1.3 ClientHello -> 1.2 Handshake" \
            "$P_SRV debug_level=4 auth_mode=required" \
            "$O_NEXT_CLI -tls1_2 -split_send_frag 32 -cert $DATA_FILES_PATH/server5.crt -key $DATA_FILES_PATH/server5.key" \
            0 \
            -s "reassembled record" \
            -s "handshake fragment: 0 \\.\\. 32 of [0-9]\\+ msglen 32" \
            -s "waiting for more fragments (32"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_certificate_authentication
run_test    "Handshake defragmentation on server: len=16, TLS 1.3" \
            "$P_SRV debug_level=4 auth_mode=required" \
            "$O_NEXT_CLI -tls1_3 -split_send_frag 16 -cert $DATA_FILES_PATH/server5.crt -key $DATA_FILES_PATH/server5.key" \
            0 \
            -s "reassembled record" \
            -s "handshake fragment: 0 \\.\\. 16 of [0-9]\\+ msglen 16" \
            -s "waiting for more fragments (16"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_2
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_certificate_authentication
run_test    "Handshake defragmentation on server: len=16, TLS 1.2  TLS 1.3 ClientHello -> 1.2 Handshake" \
            "$P_SRV debug_level=4 auth_mode=required" \
            "$O_NEXT_CLI -tls1_2 -split_send_frag 16 -cert $DATA_FILES_PATH/server5.crt -key $DATA_FILES_PATH/server5.key" \
            0 \
            -s "reassembled record" \
            -s "handshake fragment: 0 \\.\\. 16 of [0-9]\\+ msglen 16" \
            -s "waiting for more fragments (16"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_certificate_authentication
run_test    "Handshake defragmentation on server: len=13, TLS 1.3" \
            "$P_SRV debug_level=4 auth_mode=required" \
            "$O_NEXT_CLI -tls1_3 -split_send_frag 13 -cert $DATA_FILES_PATH/server5.crt -key $DATA_FILES_PATH/server5.key" \
            0 \
            -s "reassembled record" \
            -s "handshake fragment: 0 \\.\\. 13 of [0-9]\\+ msglen 13" \
            -s "waiting for more fragments (13"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_2
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_certificate_authentication
run_test    "Handshake defragmentation on server: len=13, TLS 1.2  TLS 1.3 ClientHello -> 1.2 Handshake" \
            "$P_SRV debug_level=4 auth_mode=required" \
            "$O_NEXT_CLI -tls1_2 -split_send_frag 13 -cert $DATA_FILES_PATH/server5.crt -key $DATA_FILES_PATH/server5.key" \
            0 \
            -s "reassembled record" \
            -s "handshake fragment: 0 \\.\\. 13 of [0-9]\\+ msglen 13" \
            -s "waiting for more fragments (13"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_certificate_authentication
run_test    "Handshake defragmentation on server: len=5, TLS 1.3" \
            "$P_SRV debug_level=4 auth_mode=required" \
            "$O_NEXT_CLI -tls1_3 -split_send_frag 5 -cert $DATA_FILES_PATH/server5.crt -key $DATA_FILES_PATH/server5.key" \
            0 \
            -s "reassembled record" \
            -s "handshake fragment: 0 \\.\\. 5 of [0-9]\\+ msglen 5" \
            -s "waiting for more fragments (5"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_2
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_certificate_authentication
run_test    "Handshake defragmentation on server: len=5, TLS 1.2  TLS 1.3 ClientHello -> 1.2 Handshake" \
            "$P_SRV debug_level=4 auth_mode=required" \
            "$O_NEXT_CLI -tls1_2 -split_send_frag 5 -cert $DATA_FILES_PATH/server5.crt -key $DATA_FILES_PATH/server5.key" \
            0 \
            -s "reassembled record" \
            -s "handshake fragment: 0 \\.\\. 5 of [0-9]\\+ msglen 5" \
            -s "waiting for more fragments (5"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_certificate_authentication
run_test    "Handshake defragmentation on server: len=4, TLS 1.3" \
            "$P_SRV debug_level=4 auth_mode=required" \
            "$O_NEXT_CLI -tls1_3 -split_send_frag 4 -cert $DATA_FILES_PATH/server5.crt -key $DATA_FILES_PATH/server5.key" \
            0 \
            -s "reassembled record" \
            -s "handshake fragment: 0 \\.\\. 4 of [0-9]\\+ msglen 4" \
            -s "waiting for more fragments (4"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_2
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_certificate_authentication
run_test    "Handshake defragmentation on server: len=4, TLS 1.2  TLS 1.3 ClientHello -> 1.2 Handshake" \
            "$P_SRV debug_level=4 auth_mode=required" \
            "$O_NEXT_CLI -tls1_2 -split_send_frag 4 -cert $DATA_FILES_PATH/server5.crt -key $DATA_FILES_PATH/server5.key" \
            0 \
            -s "reassembled record" \
            -s "handshake fragment: 0 \\.\\. 4 of [0-9]\\+ msglen 4" \
            -s "waiting for more fragments (4"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_certificate_authentication
run_test    "Handshake defragmentation on server: len=3, TLS 1.3" \
            "$P_SRV debug_level=4 auth_mode=required" \
            "$O_NEXT_CLI -tls1_3 -split_send_frag 3 -cert $DATA_FILES_PATH/server5.crt -key $DATA_FILES_PATH/server5.key" \
            1 \
            -s "<= parse client hello" \
            -s "handshake message too short: 3" \
            -s "SSL - An invalid SSL record was received"

requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_2
requires_config_enabled MBEDTLS_SSL_PROTO_TLS1_3
requires_certificate_authentication
run_test    "Handshake defragmentation on server: len=3, TLS 1.3 ClientHello -> 1.2 Handshake" \
            "$P_SRV debug_level=4 auth_mode=required" \
            "$O_NEXT_CLI -tls1_2 -split_send_frag 3 -cert $DATA_FILES_PATH/server5.crt -key $DATA_FILES_PATH/server5.key" \
            1 \
            -s "<= parse client hello" \
            -s "handshake message too short: 3" \
            -s "SSL - An invalid SSL record was received"
