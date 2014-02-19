#!/bin/bash

killall -q openssl ssl_server ssl_server2

let "tests = 0"
let "failed = 0"
let "skipped = 0"

MODES="ssl3 tls1 tls1_1 tls1_2"
VERIFIES="NO YES"
TYPES="ECDSA RSA PSK"
OPENSSL=openssl
FILTER=""
VERBOSE=""

# Parse arguments
#
until [ -z "$1" ]
do
  case "$1" in
    -f|--filter)
      # Filter ciphersuites
      shift
      FILTER=$1
      ;;
    -m|--modes)
      # Perform modes
      shift
      MODES=$1
      ;;
    -t|--types)
      # Key exchange types
      shift
      TYPES=$1
      ;;
    -V|--verify)
      # Verifiction modes
      shift
      VERIFIES=$1
      ;;
    -v|--verbose)
      # Set verbosity
      shift
      VERBOSE=1
      ;;
    -h|--help)
      # print help
      echo "Usage: $0"
      echo -e "  -f|--filter\tFilter ciphersuites to test (Default: all)"
      echo -e "  -h|--help\t\tPrint this help."
      echo -e "  -m|--modes\tWhich modes to perform (Default: \"ssl3 tls1 tls1_1 tls1_2\")"
      echo -e "  -t|--types\tWhich key exchange type to perform (Default: \"ECDSA RSA PSK\")"
      echo -e "  -V|--verify\tWhich verification modes to perform (Default: \"NO YES\")"
      echo -e "  -v|--verbose\t\tSet verbose output."
      exit 1
      ;;
    *)
      # print error
      echo "Unknown argument: '$1'"
      exit 1
      ;;
  esac
  shift
done

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

  echo "$NEW_LIST"
}

setup_ciphersuites()
{
    P_CIPHERS=""
    O_CIPHERS=""

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

    # Filter ciphersuites
    if [ "X" != "X$FILTER" ];
    then
        O_CIPHERS=$( filter "$O_CIPHERS" "$FILTER" )
        P_CIPHERS=$( filter "$P_CIPHERS" "$FILTER" )
    fi

}

add_polarssl_ciphersuites()
{
    ADD_CIPHERS=""

    case $TYPE in

        "ECDSA")
            if [ "$MODE" != "ssl3" ];
            then
                ADD_CIPHERS="$ADD_CIPHERS                           \
                    TLS-ECDHE-ECDSA-WITH-CAMELLIA-128-CBC-SHA256    \
                    TLS-ECDHE-ECDSA-WITH-CAMELLIA-256-CBC-SHA384    \
                    TLS-ECDH-ECDSA-WITH-CAMELLIA-128-CBC-SHA256     \
                    TLS-ECDH-ECDSA-WITH-CAMELLIA-256-CBC-SHA384     \
                    "
            fi
            if [ "$MODE" = "tls1_2" ];
            then
                ADD_CIPHERS="$ADD_CIPHERS                           \
                    TLS-ECDHE-ECDSA-WITH-CAMELLIA-128-GCM-SHA256    \
                    TLS-ECDHE-ECDSA-WITH-CAMELLIA-256-GCM-SHA384    \
                    TLS-ECDH-ECDSA-WITH-CAMELLIA-128-GCM-SHA256     \
                    TLS-ECDH-ECDSA-WITH-CAMELLIA-256-GCM-SHA384     \
                    "
            fi
            ;;

        "RSA")
            if [ "$MODE" != "ssl3" ];
            then
                ADD_CIPHERS="$ADD_CIPHERS                       \
                    TLS-ECDHE-RSA-WITH-CAMELLIA-128-CBC-SHA256  \
                    TLS-ECDHE-RSA-WITH-CAMELLIA-256-CBC-SHA384  \
                    "
            fi
            if [ "$MODE" = "tls1_2" ];
            then
                ADD_CIPHERS="$ADD_CIPHERS                       \
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
            ADD_CIPHERS="$ADD_CIPHERS                    \
                TLS-DHE-PSK-WITH-RC4-128-SHA             \
                TLS-DHE-PSK-WITH-3DES-EDE-CBC-SHA        \
                TLS-DHE-PSK-WITH-AES-128-CBC-SHA         \
                TLS-DHE-PSK-WITH-AES-256-CBC-SHA         \
                TLS-DHE-PSK-WITH-NULL-SHA                \
                TLS-PSK-WITH-NULL-SHA                    \
                TLS-RSA-PSK-WITH-RC4-128-SHA             \
                TLS-RSA-PSK-WITH-3DES-EDE-CBC-SHA        \
                TLS-RSA-PSK-WITH-AES-256-CBC-SHA         \
                TLS-RSA-PSK-WITH-AES-128-CBC-SHA         \
                TLS-RSA-WITH-NULL-SHA                    \
                TLS-RSA-WITH-NULL-MD5                    \
                TLS-PSK-WITH-AES-128-CBC-SHA256          \
                TLS-PSK-WITH-AES-256-CBC-SHA384          \
                TLS-DHE-PSK-WITH-AES-128-CBC-SHA256      \
                TLS-DHE-PSK-WITH-AES-256-CBC-SHA384      \
                TLS-PSK-WITH-NULL-SHA256                 \
                TLS-PSK-WITH-NULL-SHA384                 \
                TLS-DHE-PSK-WITH-NULL-SHA256             \
                TLS-DHE-PSK-WITH-NULL-SHA384             \
                TLS-RSA-PSK-WITH-AES-256-CBC-SHA384      \
                TLS-RSA-PSK-WITH-AES-128-CBC-SHA256      \
                TLS-RSA-PSK-WITH-NULL-SHA256             \
                TLS-RSA-PSK-WITH-NULL-SHA384             \
                TLS-DHE-PSK-WITH-CAMELLIA-128-CBC-SHA256 \
                TLS-DHE-PSK-WITH-CAMELLIA-256-CBC-SHA384 \
                TLS-PSK-WITH-CAMELLIA-128-CBC-SHA256     \
                TLS-PSK-WITH-CAMELLIA-256-CBC-SHA384     \
                TLS-RSA-PSK-WITH-CAMELLIA-256-CBC-SHA384 \
                TLS-RSA-PSK-WITH-CAMELLIA-128-CBC-SHA256 \
                "
            if [ "$MODE" != "ssl3" ];
            then
                ADD_CIPHERS="$ADD_CIPHERS                       \
                    TLS-ECDHE-PSK-WITH-AES-256-CBC-SHA          \
                    TLS-ECDHE-PSK-WITH-AES-128-CBC-SHA          \
                    TLS-ECDHE-PSK-WITH-3DES-EDE-CBC-SHA         \
                    TLS-ECDHE-PSK-WITH-RC4-128-SHA              \
                    TLS-ECDHE-PSK-WITH-NULL-SHA                 \
                    TLS-ECDHE-PSK-WITH-AES-256-CBC-SHA384       \
                    TLS-ECDHE-PSK-WITH-CAMELLIA-256-CBC-SHA384  \
                    TLS-ECDHE-PSK-WITH-AES-128-CBC-SHA256       \
                    TLS-ECDHE-PSK-WITH-CAMELLIA-128-CBC-SHA256  \
                    TLS-ECDHE-PSK-WITH-NULL-SHA384              \
                    TLS-ECDHE-PSK-WITH-NULL-SHA256              \
                    "
            fi
            if [ "$MODE" = "tls1_2" ];
            then
                ADD_CIPHERS="$ADD_CIPHERS                       \
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

    # Filter new ciphersuites and add them
    if [ "X" != "X$FILTER" ];
    then
        ADD_CIPHERS=$( filter "$ADD_CIPHERS" "$FILTER" )
    fi
    P_CIPHERS="$P_CIPHERS $ADD_CIPHERS"
}

setup_arguments()
{
    # avoid an avalanche of errors due to typos
    case $MODE in
        ssl3|tls1|tls1_1|tls1_2)
            ;;
        *)
            echo "error: invalid mode: $MODE" >&2
            exit 1;
    esac

    P_SERVER_ARGS="server_addr=0.0.0.0 force_version=$MODE"
    P_CLIENT_ARGS="server_name=0.0.0.0 force_version=$MODE"
    O_SERVER_ARGS="-www -quiet -cipher NULL,ALL -$MODE"
    O_CLIENT_ARGS="-$MODE"

    if [ "X$VERIFY" = "XYES" ];
    then
        P_SERVER_ARGS="$P_SERVER_ARGS ca_file=data_files/test-ca_cat12.crt auth_mode=required"
        P_CLIENT_ARGS="$P_CLIENT_ARGS ca_file=data_files/test-ca_cat12.crt"
        O_SERVER_ARGS="$O_SERVER_ARGS -CAfile data_files/test-ca_cat12.crt -Verify 10"
        O_CLIENT_ARGS="$O_CLIENT_ARGS -CAfile data_files/test-ca_cat12.crt"
    fi

    case $TYPE in
        "ECDSA")
            P_SERVER_ARGS="$P_SERVER_ARGS crt_file=data_files/server5.crt key_file=data_files/server5.key"
            P_CLIENT_ARGS="$P_CLIENT_ARGS crt_file=data_files/server6.crt key_file=data_files/server6.key"
            O_SERVER_ARGS="$O_SERVER_ARGS -cert data_files/server5.crt -key data_files/server5.key"
            O_CLIENT_ARGS="$O_CLIENT_ARGS -cert data_files/server6.crt -key data_files/server6.key"
            ;;

        "RSA")
            P_SERVER_ARGS="$P_SERVER_ARGS crt_file=data_files/server1.crt key_file=data_files/server1.key"
            P_CLIENT_ARGS="$P_CLIENT_ARGS crt_file=data_files/server2.crt key_file=data_files/server2.key"
            O_SERVER_ARGS="$O_SERVER_ARGS -cert data_files/server1.crt -key data_files/server1.key"
            O_CLIENT_ARGS="$O_CLIENT_ARGS -cert data_files/server2.crt -key data_files/server2.key"
            ;;

        "PSK")
            P_SERVER_ARGS="$P_SERVER_ARGS psk=6162636465666768696a6b6c6d6e6f70"
            P_CLIENT_ARGS="$P_CLIENT_ARGS psk=6162636465666768696a6b6c6d6e6f70"
            # openssl s_server won't start without certificates...
            O_SERVER_ARGS="$O_SERVER_ARGS -psk 6162636465666768696a6b6c6d6e6f70 -cert data_files/server1.crt -key data_files/server1.key"
            O_CLIENT_ARGS="$O_CLIENT_ARGS -psk 6162636465666768696a6b6c6d6e6f70"
            ;;
    esac
}

# start_server <name>
# also saves name and command
start_server() {
    echo "-----------"

    case $1 in
        [Oo]pen*)
            SERVER_CMD="$OPENSSL s_server $O_SERVER_ARGS"
            ;;
        [Pp]olar*)
            SERVER_CMD="../programs/ssl/ssl_server2 $P_SERVER_ARGS"
            ;;
        *)
            echo "error: invalid server name: $1" >&2
            exit 1
            ;;
    esac
    SERVER_NAME=$1

    log "$SERVER_CMD"
    $SERVER_CMD >/dev/null 2>&1 &
    PROCESS_ID=$!

    sleep 1
}

# terminate the running server (try closing it cleanly if possible)
stop_server() {
    case $SERVER_NAME in
        [Pp]olar*)
            echo SERVERQUIT | $OPENSSL s_client $O_CLIENT_ARGS >/dev/null 2>&1
            sleep 1
            ;;
    esac

    kill $PROCESS_ID 2>/dev/null
    wait $PROCESS_ID 2>/dev/null
}

# run_client <name> <cipher>
run_client() {
    # run the command and interpret result
    case $1 in
        [Oo]pen*)
            CLIENT_CMD="$OPENSSL s_client $O_CLIENT_ARGS -cipher $2"
            log "$CLIENT_CMD"
            OUTPUT="$( ( echo -e 'GET HTTP/1.0'; echo; ) | $CLIENT_CMD 2>&1 )"
            EXIT=$?

            if [ "$EXIT" == "0" ]; then
                RESULT=0
            else
                SUPPORTED="$( echo $OUTPUT | grep 'Cipher is (NONE)' )"
                if [ "X$SUPPORTED" != "X" ]; then
                    RESULT=1
                else
                    RESULT=2
                fi
            fi
            ;;

        [Pp]olar*)
            CLIENT_CMD="../programs/ssl/ssl_client2 $P_CLIENT_ARGS force_ciphersuite=$2"
            log "$CLIENT_CMD"
            OUTPUT="$( $CLIENT_CMD )"
            EXIT=$?

            case $EXIT in
                "0")    RESULT=0    ;;
                "2")    RESULT=1    ;;
                *)      RESULT=2    ;;
            esac
            ;;

        *)
            echo "error: invalid client name: $1" >&2
            exit 1
            ;;
    esac

    # report and count result
    let "tests++"
    echo -n "$SERVER_NAME Server - $1 Client - $2 : $EXIT - "
    case $RESULT in
        "0")
            echo Success
            ;;
        "1")
            echo "Ciphersuite not supported"
            let "skipped++"
            ;;
        "2")
            echo Failed
            echo "$SERVER_CMD"
            echo "$CLIENT_CMD"
            echo "$OUTPUT"
            let "failed++"
            ;;
    esac
}

for VERIFY in $VERIFIES; do
    for MODE in $MODES; do
        echo "-----------"
        echo "Running for $MODE (Verify: $VERIFY)"
        for TYPE in $TYPES; do

            setup_arguments
            setup_ciphersuites

            start_server "OpenSSL"

            for i in $P_CIPHERS; do
                run_client PolarSSL $i
            done

            stop_server

            start_server "PolarSSL"

            for i in $O_CIPHERS; do
                run_client OpenSSL $i
            done

            echo "-----------"
            add_polarssl_ciphersuites

            for i in $P_CIPHERS; do
                run_client PolarSSL $i
            done

            stop_server

        done
    done
done

echo ""
echo "-------------------------------------------------------------------------"
echo ""

if (( failed != 0 ));
then
    echo -n "FAILED"
else
    echo -n "PASSED"
fi

let "passed = tests - failed"
echo " ($passed / $tests tests ($skipped skipped))"

exit $failed
