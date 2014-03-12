#!/bin/bash

# Test interop with OpenSSL for each common ciphersuite and version.
# Also test selfop for ciphersuites not shared with OpenSSL.

set -u

let "tests = 0"
let "failed = 0"
let "skipped = 0"
let "srvmem = 0"

# default values, can be overriden by the environment
: ${P_SRV:=../programs/ssl/ssl_server2}
: ${P_CLI:=../programs/ssl/ssl_client2}
: ${OPENSSL:=openssl}

MODES="ssl3 tls1 tls1_1 tls1_2"
VERIFIES="NO YES"
TYPES="ECDSA RSA PSK"
FILTER=""
VERBOSE=""
MEMCHECK=0

print_usage() {
    echo "Usage: $0"
    echo -e "  -f|--filter\tFilter ciphersuites to test (Default: all)"
    echo -e "  -h|--help\t\tPrint this help."
    echo -e "  -m|--modes\tWhich modes to perform (Default: \"ssl3 tls1 tls1_1 tls1_2\")"
    echo -e "  -t|--types\tWhich key exchange type to perform (Default: \"ECDSA RSA PSK\")"
    echo -e "  -V|--verify\tWhich verification modes to perform (Default: \"NO YES\")"
    echo -e "  -M, --memcheck\tCheck memory leaks and errors."
    echo -e "  -v|--verbose\t\tSet verbose output."
}

get_options() {
    while [ $# -gt 0 ]; do
        case "$1" in
            -f|--filter)
                shift; FILTER=$1
                ;;
            -m|--modes)
                shift; MODES=$1
                ;;
            -t|--types)
                shift; TYPES=$1
                ;;
            -V|--verify)
                shift; VERIFIES=$1
                ;;
            -v|--verbose)
                VERBOSE=1
                ;;
            -M|--memcheck)
                MEMCHECK=1
                ;;
            -h|--help)
                print_usage
                exit 0
                ;;
            *)
                echo "Unknown argument: '$1'"
                print_usage
                exit 1
                ;;
        esac
        shift
    done
}

log() {
  if [ "X" != "X$VERBOSE" ]; then
    echo "$@"
  fi
}

filter()
{
  LIST=$1
  FILTER=$2

  NEW_LIST=""

  for i in $LIST;
  do
    NEW_LIST="$NEW_LIST $( echo "$i" | grep "$FILTER" )"
  done

  # normalize whitespace
  echo "$NEW_LIST" | sed -e 's/[[:space:]]\+/ /g' -e 's/^ //' -e 's/ $//'
}

filter_ciphersuites()
{
    if [ "X" != "X$FILTER" ];
    then
        P_CIPHERS=$( filter "$P_CIPHERS" "$FILTER" )
        O_CIPHERS=$( filter "$O_CIPHERS" "$FILTER" )
        G_CIPHERS=$( filter "$G_CIPHERS" "$FILTER" )
    fi
}

reset_ciphersuites()
{
    P_CIPHERS=""
    O_CIPHERS=""
    G_CIPHERS=""
}

add_openssl_ciphersuites()
{
    case $TYPE in

        "ECDSA")
            if [ "$MODE" != "ssl3" ];
            then
                P_CIPHERS="$P_CIPHERS                       \
                    TLS-ECDHE-ECDSA-WITH-NULL-SHA           \
                    TLS-ECDHE-ECDSA-WITH-RC4-128-SHA        \
                    TLS-ECDHE-ECDSA-WITH-3DES-EDE-CBC-SHA   \
                    TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA    \
                    TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA    \
                    TLS-ECDH-ECDSA-WITH-NULL-SHA            \
                    TLS-ECDH-ECDSA-WITH-RC4-128-SHA         \
                    TLS-ECDH-ECDSA-WITH-3DES-EDE-CBC-SHA    \
                    TLS-ECDH-ECDSA-WITH-AES-128-CBC-SHA     \
                    TLS-ECDH-ECDSA-WITH-AES-256-CBC-SHA     \
                    "
                O_CIPHERS="$O_CIPHERS               \
                    ECDHE-ECDSA-NULL-SHA            \
                    ECDHE-ECDSA-RC4-SHA             \
                    ECDHE-ECDSA-DES-CBC3-SHA        \
                    ECDHE-ECDSA-AES128-SHA          \
                    ECDHE-ECDSA-AES256-SHA          \
                    ECDH-ECDSA-NULL-SHA             \
                    ECDH-ECDSA-RC4-SHA              \
                    ECDH-ECDSA-DES-CBC3-SHA         \
                    ECDH-ECDSA-AES128-SHA           \
                    ECDH-ECDSA-AES256-SHA           \
                    "
            fi
            if [ "$MODE" = "tls1_2" ];
            then
                P_CIPHERS="$P_CIPHERS                               \
                    TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256         \
                    TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384         \
                    TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256         \
                    TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384         \
                    TLS-ECDH-ECDSA-WITH-AES-128-CBC-SHA256          \
                    TLS-ECDH-ECDSA-WITH-AES-256-CBC-SHA384          \
                    TLS-ECDH-ECDSA-WITH-AES-128-GCM-SHA256          \
                    TLS-ECDH-ECDSA-WITH-AES-256-GCM-SHA384          \
                    "
                O_CIPHERS="$O_CIPHERS               \
                    ECDHE-ECDSA-AES128-SHA256       \
                    ECDHE-ECDSA-AES256-SHA384       \
                    ECDHE-ECDSA-AES128-GCM-SHA256   \
                    ECDHE-ECDSA-AES256-GCM-SHA384   \
                    ECDH-ECDSA-AES128-SHA256        \
                    ECDH-ECDSA-AES256-SHA384        \
                    ECDH-ECDSA-AES128-GCM-SHA256    \
                    ECDH-ECDSA-AES256-GCM-SHA384    \
                    "
            fi
            ;;

        "RSA")
            P_CIPHERS="$P_CIPHERS                       \
                TLS-DHE-RSA-WITH-AES-128-CBC-SHA        \
                TLS-DHE-RSA-WITH-AES-256-CBC-SHA        \
                TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA   \
                TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA   \
                TLS-DHE-RSA-WITH-3DES-EDE-CBC-SHA       \
                TLS-RSA-WITH-AES-256-CBC-SHA            \
                TLS-RSA-WITH-CAMELLIA-256-CBC-SHA       \
                TLS-RSA-WITH-AES-128-CBC-SHA            \
                TLS-RSA-WITH-CAMELLIA-128-CBC-SHA       \
                TLS-RSA-WITH-3DES-EDE-CBC-SHA           \
                TLS-RSA-WITH-RC4-128-SHA                \
                TLS-RSA-WITH-RC4-128-MD5                \
                TLS-RSA-WITH-NULL-MD5                   \
                TLS-RSA-WITH-NULL-SHA                   \
                TLS-RSA-WITH-DES-CBC-SHA                \
                TLS-DHE-RSA-WITH-DES-CBC-SHA            \
                "
            O_CIPHERS="$O_CIPHERS               \
                DHE-RSA-AES128-SHA              \
                DHE-RSA-AES256-SHA              \
                DHE-RSA-CAMELLIA128-SHA         \
                DHE-RSA-CAMELLIA256-SHA         \
                EDH-RSA-DES-CBC3-SHA            \
                AES256-SHA                      \
                CAMELLIA256-SHA                 \
                AES128-SHA                      \
                CAMELLIA128-SHA                 \
                DES-CBC3-SHA                    \
                RC4-SHA                         \
                RC4-MD5                         \
                NULL-MD5                        \
                NULL-SHA                        \
                DES-CBC-SHA                     \
                EDH-RSA-DES-CBC-SHA             \
                "
            if [ "$MODE" != "ssl3" ];
            then
                P_CIPHERS="$P_CIPHERS                       \
                    TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA      \
                    TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA      \
                    TLS-ECDHE-RSA-WITH-3DES-EDE-CBC-SHA     \
                    TLS-ECDHE-RSA-WITH-RC4-128-SHA          \
                    TLS-ECDHE-RSA-WITH-NULL-SHA             \
                    "
                O_CIPHERS="$O_CIPHERS               \
                    ECDHE-RSA-AES256-SHA            \
                    ECDHE-RSA-AES128-SHA            \
                    ECDHE-RSA-DES-CBC3-SHA          \
                    ECDHE-RSA-RC4-SHA               \
                    ECDHE-RSA-NULL-SHA              \
                    "
            fi
            if [ "$MODE" = "tls1_2" ];
            then
                P_CIPHERS="$P_CIPHERS                       \
                    TLS-RSA-WITH-NULL-SHA256                \
                    TLS-RSA-WITH-AES-128-CBC-SHA256         \
                    TLS-DHE-RSA-WITH-AES-128-CBC-SHA256     \
                    TLS-RSA-WITH-AES-256-CBC-SHA256         \
                    TLS-DHE-RSA-WITH-AES-256-CBC-SHA256     \
                    TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256   \
                    TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA384   \
                    TLS-RSA-WITH-AES-128-GCM-SHA256         \
                    TLS-RSA-WITH-AES-256-GCM-SHA384         \
                    TLS-DHE-RSA-WITH-AES-128-GCM-SHA256     \
                    TLS-DHE-RSA-WITH-AES-256-GCM-SHA384     \
                    TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256   \
                    TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384   \
                    "
                O_CIPHERS="$O_CIPHERS           \
                    NULL-SHA256                 \
                    AES128-SHA256               \
                    DHE-RSA-AES128-SHA256       \
                    AES256-SHA256               \
                    DHE-RSA-AES256-SHA256       \
                    ECDHE-RSA-AES128-SHA256     \
                    ECDHE-RSA-AES256-SHA384     \
                    AES128-GCM-SHA256           \
                    DHE-RSA-AES128-GCM-SHA256   \
                    AES256-GCM-SHA384           \
                    DHE-RSA-AES256-GCM-SHA384   \
                    ECDHE-RSA-AES128-GCM-SHA256 \
                    ECDHE-RSA-AES256-GCM-SHA384 \
                    "
            fi
            ;;

        "PSK")
            P_CIPHERS="$P_CIPHERS                       \
                TLS-PSK-WITH-RC4-128-SHA                \
                TLS-PSK-WITH-3DES-EDE-CBC-SHA           \
                TLS-PSK-WITH-AES-128-CBC-SHA            \
                TLS-PSK-WITH-AES-256-CBC-SHA            \
                "
            O_CIPHERS="$O_CIPHERS               \
                PSK-RC4-SHA                     \
                PSK-3DES-EDE-CBC-SHA            \
                PSK-AES128-CBC-SHA              \
                PSK-AES256-CBC-SHA              \
                "
            ;;
    esac
}

add_gnutls_ciphersuites()
{
    # TODO: add to G_CIPHERS too
    case $TYPE in

        "ECDSA")
            if [ "$MODE" = "tls1_2" ];
            then
                P_CIPHERS="$P_CIPHERS                               \
                    TLS-ECDHE-ECDSA-WITH-CAMELLIA-128-CBC-SHA256    \
                    TLS-ECDHE-ECDSA-WITH-CAMELLIA-256-CBC-SHA384    \
                    TLS-ECDHE-ECDSA-WITH-CAMELLIA-128-GCM-SHA256    \
                    TLS-ECDHE-ECDSA-WITH-CAMELLIA-256-GCM-SHA384    \
                    "
            fi
            ;;

        "RSA")
            if [ "$MODE" = "tls1_2" ];
            then
                P_CIPHERS="$P_CIPHERS                           \
                    TLS-ECDHE-RSA-WITH-CAMELLIA-128-CBC-SHA256  \
                    TLS-ECDHE-RSA-WITH-CAMELLIA-256-CBC-SHA384  \
                    TLS-RSA-WITH-CAMELLIA-128-CBC-SHA256        \
                    TLS-RSA-WITH-CAMELLIA-256-CBC-SHA256        \
                    TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA256    \
                    TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA256    \
                    TLS-ECDHE-RSA-WITH-CAMELLIA-128-GCM-SHA256  \
                    TLS-ECDHE-RSA-WITH-CAMELLIA-256-GCM-SHA384  \
                    TLS-DHE-RSA-WITH-CAMELLIA-128-GCM-SHA256    \
                    TLS-DHE-RSA-WITH-CAMELLIA-256-GCM-SHA384    \
                    TLS-RSA-WITH-CAMELLIA-128-GCM-SHA256        \
                    TLS-RSA-WITH-CAMELLIA-256-GCM-SHA384        \
                    "
            fi
            ;;

        "PSK")
            # GnuTLS 3.2.11 (2014-02-13) requires TLS 1.x for most *PSK suites
            if [ "$MODE" != "ssl3" ];
            then
                P_CIPHERS="$P_CIPHERS                           \
                    TLS-ECDHE-PSK-WITH-AES-256-CBC-SHA          \
                    TLS-ECDHE-PSK-WITH-AES-128-CBC-SHA          \
                    TLS-ECDHE-PSK-WITH-3DES-EDE-CBC-SHA         \
                    TLS-DHE-PSK-WITH-3DES-EDE-CBC-SHA           \
                    TLS-DHE-PSK-WITH-AES-128-CBC-SHA            \
                    TLS-DHE-PSK-WITH-AES-256-CBC-SHA            \
                    TLS-RSA-PSK-WITH-3DES-EDE-CBC-SHA           \
                    TLS-RSA-PSK-WITH-AES-256-CBC-SHA            \
                    TLS-RSA-PSK-WITH-AES-128-CBC-SHA            \
                    TLS-RSA-WITH-NULL-SHA                       \
                    TLS-RSA-WITH-NULL-MD5                       \
                    "
            fi
            if [ "$MODE" = "tls1_2" ];
            then
                P_CIPHERS="$P_CIPHERS                           \
                    TLS-ECDHE-PSK-WITH-AES-256-CBC-SHA384       \
                    TLS-ECDHE-PSK-WITH-CAMELLIA-256-CBC-SHA384  \
                    TLS-ECDHE-PSK-WITH-AES-128-CBC-SHA256       \
                    TLS-ECDHE-PSK-WITH-CAMELLIA-128-CBC-SHA256  \
                    TLS-ECDHE-PSK-WITH-NULL-SHA384              \
                    TLS-ECDHE-PSK-WITH-NULL-SHA256              \
                    TLS-PSK-WITH-AES-128-CBC-SHA256             \
                    TLS-PSK-WITH-AES-256-CBC-SHA384             \
                    TLS-DHE-PSK-WITH-AES-128-CBC-SHA256         \
                    TLS-DHE-PSK-WITH-AES-256-CBC-SHA384         \
                    TLS-PSK-WITH-NULL-SHA256                    \
                    TLS-PSK-WITH-NULL-SHA384                    \
                    TLS-DHE-PSK-WITH-NULL-SHA256                \
                    TLS-DHE-PSK-WITH-NULL-SHA384                \
                    TLS-RSA-PSK-WITH-AES-256-CBC-SHA384         \
                    TLS-RSA-PSK-WITH-AES-128-CBC-SHA256         \
                    TLS-RSA-PSK-WITH-NULL-SHA256                \
                    TLS-RSA-PSK-WITH-NULL-SHA384                \
                    TLS-DHE-PSK-WITH-CAMELLIA-128-CBC-SHA256    \
                    TLS-DHE-PSK-WITH-CAMELLIA-256-CBC-SHA384    \
                    TLS-PSK-WITH-CAMELLIA-128-CBC-SHA256        \
                    TLS-PSK-WITH-CAMELLIA-256-CBC-SHA384        \
                    TLS-RSA-PSK-WITH-CAMELLIA-256-CBC-SHA384    \
                    TLS-RSA-PSK-WITH-CAMELLIA-128-CBC-SHA256    \
                    TLS-PSK-WITH-AES-128-GCM-SHA256             \
                    TLS-PSK-WITH-AES-256-GCM-SHA384             \
                    TLS-DHE-PSK-WITH-AES-128-GCM-SHA256         \
                    TLS-DHE-PSK-WITH-AES-256-GCM-SHA384         \
                    TLS-RSA-PSK-WITH-CAMELLIA-128-GCM-SHA256    \
                    TLS-RSA-PSK-WITH-CAMELLIA-256-GCM-SHA384    \
                    TLS-PSK-WITH-CAMELLIA-128-GCM-SHA256        \
                    TLS-PSK-WITH-CAMELLIA-256-GCM-SHA384        \
                    TLS-DHE-PSK-WITH-CAMELLIA-128-GCM-SHA256    \
                    TLS-DHE-PSK-WITH-CAMELLIA-256-GCM-SHA384    \
                    TLS-RSA-PSK-WITH-AES-256-GCM-SHA384         \
                    TLS-RSA-PSK-WITH-AES-128-GCM-SHA256         \
                    TLS-RSA-WITH-NULL-SHA256                    \
                    "
            fi
            ;;
    esac
}

add_polarssl_ciphersuites()
{
    case $TYPE in

        "ECDSA")
            if [ "$MODE" != "ssl3" ];
            then
                P_CIPHERS="$P_CIPHERS                               \
                    TLS-ECDH-ECDSA-WITH-CAMELLIA-128-CBC-SHA256     \
                    TLS-ECDH-ECDSA-WITH-CAMELLIA-256-CBC-SHA384     \
                    "
            fi
            if [ "$MODE" = "tls1_2" ];
            then
                P_CIPHERS="$P_CIPHERS                               \
                    TLS-ECDH-ECDSA-WITH-CAMELLIA-128-GCM-SHA256     \
                    TLS-ECDH-ECDSA-WITH-CAMELLIA-256-GCM-SHA384     \
                    "
            fi
            ;;

        "RSA")
            ;;

        "PSK")
            P_CIPHERS="$P_CIPHERS                        \
                TLS-PSK-WITH-NULL-SHA                    \
                TLS-DHE-PSK-WITH-RC4-128-SHA             \
                TLS-DHE-PSK-WITH-NULL-SHA                \
                TLS-RSA-PSK-WITH-RC4-128-SHA             \
                "
            if [ "$MODE" != "ssl3" ];
            then
                P_CIPHERS="$P_CIPHERS                    \
                    TLS-ECDHE-PSK-WITH-RC4-128-SHA       \
                    TLS-ECDHE-PSK-WITH-NULL-SHA          \
                    "
            fi
            ;;
    esac
}

setup_arguments()
{
    case $MODE in
        "ssl3")
            G_PRIO_MODE="+VERS-SSL3.0"
            ;;
        "tls1")
            G_PRIO_MODE="+VERS-TLS1.0"
            ;;
        "tls1_1")
            G_PRIO_MODE="+VERS-TLS1.1"
            ;;
        "tls1_2")
            G_PRIO_MODE="+VERS-TLS1.2"
            ;;
        *)
            echo "error: invalid mode: $MODE" >&2
            exit 1;
    esac

    P_SERVER_ARGS="server_addr=0.0.0.0 force_version=$MODE"
    O_SERVER_ARGS="-www -cipher NULL,ALL -$MODE"
    G_SERVER_ARGS="-p 4433 --http"
    G_PRIO_BASE="EXPORT:+PSK:+DHE-PSK:+ECDHE-PSK:+RSA-PSK:-VERS-TLS-ALL"

    P_CLIENT_ARGS="force_version=$MODE"
    O_CLIENT_ARGS="-$MODE"

    if [ "X$VERIFY" = "XYES" ];
    then
        P_SERVER_ARGS="$P_SERVER_ARGS ca_file=data_files/test-ca_cat12.crt auth_mode=required"
        O_SERVER_ARGS="$O_SERVER_ARGS -CAfile data_files/test-ca_cat12.crt -Verify 10"
        G_SERVER_ARGS="$G_SERVER_ARGS --x509cafile data_files/test-ca_cat12.crt --require-client-cert"

        P_CLIENT_ARGS="$P_CLIENT_ARGS ca_file=data_files/test-ca_cat12.crt auth_mode=required"
        O_CLIENT_ARGS="$O_CLIENT_ARGS -CAfile data_files/test-ca_cat12.crt -verify 10"
    else
        # don't request a client cert at all
        P_SERVER_ARGS="$P_SERVER_ARGS ca_file=none auth_mode=none"
        G_SERVER_ARGS="$G_SERVER_ARGS --disable-client-cert"

        # give dummy CA to clients
        P_CLIENT_ARGS="$P_CLIENT_ARGS ca_file=data_files/cli2.crt auth_mode=optional"
        O_CLIENT_ARGS="$O_CLIENT_ARGS -CAfile data_files/cli2.crt"
    fi

    case $TYPE in
        "ECDSA")
            P_SERVER_ARGS="$P_SERVER_ARGS crt_file=data_files/server5.crt key_file=data_files/server5.key"
            O_SERVER_ARGS="$O_SERVER_ARGS -cert data_files/server5.crt -key data_files/server5.key"
            G_SERVER_ARGS="$G_SERVER_ARGS --x509certfile data_files/server5.crt --x509keyfile data_files/server5.key"

            if [ "X$VERIFY" = "XYES" ]; then
                P_CLIENT_ARGS="$P_CLIENT_ARGS crt_file=data_files/server6.crt key_file=data_files/server6.key"
                O_CLIENT_ARGS="$O_CLIENT_ARGS -cert data_files/server6.crt -key data_files/server6.key"
            else
                P_CLIENT_ARGS="$P_CLIENT_ARGS crt_file=none key_file=none"
            fi
            ;;

        "RSA")
            P_SERVER_ARGS="$P_SERVER_ARGS crt_file=data_files/server2.crt key_file=data_files/server2.key"
            O_SERVER_ARGS="$O_SERVER_ARGS -cert data_files/server2.crt -key data_files/server2.key"
            G_SERVER_ARGS="$G_SERVER_ARGS --x509certfile data_files/server2.crt --x509keyfile data_files/server2.key"

            if [ "X$VERIFY" = "XYES" ]; then
                P_CLIENT_ARGS="$P_CLIENT_ARGS crt_file=data_files/server1.crt key_file=data_files/server1.key"
                O_CLIENT_ARGS="$O_CLIENT_ARGS -cert data_files/server1.crt -key data_files/server1.key"
            else
                P_CLIENT_ARGS="$P_CLIENT_ARGS crt_file=none key_file=none"
            fi
            ;;

        "PSK")
            # give RSA-PSK-capable server a RSA cert
            # (should be a separate type, but harder to close with openssl)
            P_SERVER_ARGS="$P_SERVER_ARGS psk=6162636465666768696a6b6c6d6e6f70 ca_file=none crt_file=data_files/server2.crt key_file=data_files/server2.key"
            O_SERVER_ARGS="$O_SERVER_ARGS -psk 6162636465666768696a6b6c6d6e6f70 -nocert"
            G_SERVER_ARGS="$G_SERVER_ARGS --x509certfile data_files/server2.crt --x509keyfile data_files/server2.key --pskpasswd data_files/passwd.psk"

            P_CLIENT_ARGS="$P_CLIENT_ARGS psk=6162636465666768696a6b6c6d6e6f70 crt_file=none key_file=none"
            O_CLIENT_ARGS="$O_CLIENT_ARGS -psk 6162636465666768696a6b6c6d6e6f70"
            ;;
    esac
}

# is_polar <cmd_line>
is_polar() {
    echo "$1" | grep 'ssl_server2\|ssl_client2' > /dev/null
}

# has_mem_err <log_file_name>
has_mem_err() {
    if ( grep -F 'All heap blocks were freed -- no leaks are possible' "$1" &&
         grep -F 'ERROR SUMMARY: 0 errors from 0 contexts' "$1" ) > /dev/null
    then
        return 1 # false: does not have errors
    else
        return 0 # true: has errors
    fi
}

# start_server <name>
# also saves name and command
start_server() {
    case $1 in
        [Oo]pen*)
            SERVER_CMD="$OPENSSL s_server $O_SERVER_ARGS"
            ;;
        [Gg]nu*)
            SERVER_CMD="gnutls-serv $G_SERVER_ARGS --priority $G_PRIO_BASE:$G_PRIO_MODE"
            ;;
        [Pp]olar*)
            SERVER_CMD="$P_SRV $P_SERVER_ARGS"
            if [ "$MEMCHECK" -gt 0 ]; then
                SERVER_CMD="valgrind --leak-check=full $SERVER_CMD"
            fi
            ;;
        *)
            echo "error: invalid server name: $1" >&2
            exit 1
            ;;
    esac
    SERVER_NAME=$1

    log "$SERVER_CMD"
    $SERVER_CMD >srv_out 2>&1 &
    PROCESS_ID=$!

    sleep 1
}

# terminate the running server (closing it cleanly if it is ours)
stop_server() {
    case $SERVER_NAME in
        [Pp]olar*)
            # we must force a PSK suite when in PSK mode (otherwise client
            # auth will fail), so use $O_CIPHERS
            CS=$( echo "$O_CIPHERS" | tr ' ' ':' )
            echo SERVERQUIT | \
                $OPENSSL s_client $O_CLIENT_ARGS -cipher "$CS" >/dev/null 2>&1
            ;;
        *)
            kill $PROCESS_ID 2>/dev/null
    esac

    wait $PROCESS_ID 2>/dev/null

    if [ "$MEMCHECK" -gt 0 ]; then
        if is_polar "$SERVER_CMD" && has_mem_err srv_out; then
            echo "  ! Server had memory errors"
            let "srvmem++"
            return
        fi
    fi

    rm -f srv_out
}

# kill the running server (used when killed by signal)
cleanup() {
    rm -f srv_out cli_out
    kill $PROCESS_ID
    exit 1
}

# run_client <name> <cipher>
run_client() {
    # announce what we're going to do
    let "tests++"
    VERIF=$(echo $VERIFY | tr '[:upper:]' '[:lower:]')
    TITLE="${1:0:1}->${SERVER_NAME:0:1} $MODE,$VERIF $2 "
    echo -n "$TITLE"
    LEN=`echo "$TITLE" | wc -c`
    LEN=`echo 72 - $LEN | bc`
    for i in `seq 1 $LEN`; do echo -n '.'; done; echo -n ' '

    # run the command and interpret result
    case $1 in
        [Oo]pen*)
            CLIENT_CMD="$OPENSSL s_client $O_CLIENT_ARGS -cipher $2"
            log "$CLIENT_CMD"
            ( echo -e 'GET HTTP/1.0'; echo; ) | $CLIENT_CMD > cli_out 2>&1
            EXIT=$?

            if [ "$EXIT" == "0" ]; then
                RESULT=0
            else
                if grep 'Cipher is (NONE)' cli_out >/dev/null; then
                    RESULT=1
                else
                    RESULT=2
                fi
            fi
            ;;

        [Pp]olar*)
            CLIENT_CMD="$P_CLI $P_CLIENT_ARGS force_ciphersuite=$2"
            if [ "$MEMCHECK" -gt 0 ]; then
                CLIENT_CMD="valgrind --leak-check=full $CLIENT_CMD"
            fi
            log "$CLIENT_CMD"
            $CLIENT_CMD > cli_out 2>&1
            EXIT=$?

            case $EXIT in
                "0")    RESULT=0    ;;
                "2")    RESULT=1    ;;
                *)      RESULT=2    ;;
            esac

            if [ "$MEMCHECK" -gt 0 ]; then
                if is_polar "$CLIENT_CMD" && has_mem_err cli_out; then
                    RESULT=2
                fi
            fi

            ;;

        *)
            echo "error: invalid client name: $1" >&2
            exit 1
            ;;
    esac

    # report and count result
    case $RESULT in
        "0")
            echo PASS
            ;;
        "1")
            echo SKIP
            let "skipped++"
            ;;
        "2")
            echo FAIL
            echo "  ! $SERVER_CMD"
            echo "  ! $CLIENT_CMD"
            cp srv_out c-srv-${tests}.log
            cp cli_out c-cli-${tests}.log
            echo "  ! outputs saved to c-srv-${tests}.log, c-cli-${tests}.log"
            let "failed++"
            ;;
    esac

    rm -f cli_out
}

#
# MAIN
#

# sanity checks, avoid an avalanche of errors
if [ ! -x "$P_SRV" ]; then
    echo "Command '$P_SRV' is not an executable file"
    exit 1
fi
if [ ! -x "$P_CLI" ]; then
    echo "Command '$P_CLI' is not an executable file"
    exit 1
fi
if which $OPENSSL >/dev/null 2>&1; then :; else
    echo "Command '$OPENSSL' not found"
    exit 1
fi

get_options "$@"

killall -q gnutls-serv openssl ssl_server ssl_server2
trap cleanup INT TERM HUP

for VERIFY in $VERIFIES; do
    for MODE in $MODES; do
        for TYPE in $TYPES; do

            setup_arguments

            reset_ciphersuites
            add_openssl_ciphersuites
            filter_ciphersuites

            if [ "X" != "X$P_CIPHERS" ]; then
                start_server "OpenSSL"
                for i in $P_CIPHERS; do
                    run_client PolarSSL $i
                done
                stop_server
            fi

            if [ "X" != "X$O_CIPHERS" ]; then
                start_server "PolarSSL"
                for i in $O_CIPHERS; do
                    run_client OpenSSL $i
                done
                stop_server
            fi

            reset_ciphersuites
            add_gnutls_ciphersuites
            filter_ciphersuites

            if [ "X" != "X$P_CIPHERS" ]; then
                start_server "GnuTLS"
                for i in $P_CIPHERS; do
                    run_client PolarSSL $i
                done
                stop_server
            fi

            if [ "X" != "X$G_CIPHERS" ]; then
                start_server "PolarSSL"
                for i in $G_CIPHERS; do
                    run_client GnuTLS $i
                done
                stop_server
            fi

            reset_ciphersuites
            add_openssl_ciphersuites
            add_gnutls_ciphersuites
            add_polarssl_ciphersuites
            filter_ciphersuites

            if [ "X" != "X$P_CIPHERS" ]; then
                start_server "PolarSSL"
                for i in $P_CIPHERS; do
                    run_client PolarSSL $i
                done
                stop_server
            fi

        done
    done
done

echo "------------------------------------------------------------------------"

if (( failed != 0 && srvmem != 0 ));
then
    echo -n "FAILED"
else
    echo -n "PASSED"
fi

let "passed = tests - failed"
echo " ($passed / $tests tests ($skipped skipped, $srvmem server memory errors)"

let "failed += srvmem"
exit $failed
