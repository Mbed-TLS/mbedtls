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

log () {
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

for VERIFY in $VERIFIES;
do

if [ "X$VERIFY" = "XYES" ];
then
    P_SERVER_BASE="ca_file=data_files/test-ca_cat12.crt auth_mode=required"
    P_CLIENT_BASE="ca_file=data_files/test-ca_cat12.crt"
    O_SERVER_BASE="-CAfile data_files/test-ca_cat12.crt -Verify 10"
    O_CLIENT_BASE="-CAfile data_files/test-ca_cat12.crt"
else
    P_SERVER_BASE=""
    P_CLIENT_BASE=""
    O_SERVER_BASE=""
    O_CLIENT_BASE=""
fi


for MODE in $MODES;
do

# avoid an avalanche of errors due to typos
case $MODE in
    ssl3|tls1|tls1_1|tls1_2)
        ;;
    *)
        echo "error: invalid mode: $MODE" >&2
        exit 1;
esac

echo "-----------"
echo "Running for $MODE (Verify: $VERIFY)"
echo "-----------"

for TYPE in $TYPES;
do

case $TYPE in

    "ECDSA")

        P_SERVER_ARGS="$P_SERVER_BASE crt_file=data_files/server5.crt key_file=data_files/server5.key"
        P_CLIENT_ARGS="$P_CLIENT_BASE crt_file=data_files/server6.crt key_file=data_files/server6.key"
        O_SERVER_ARGS="$O_SERVER_BASE -cert data_files/server5.crt -key data_files/server5.key"
        O_CLIENT_ARGS="$O_CLIENT_BASE -cert data_files/server6.crt -key data_files/server6.key"

        P_CIPHERS="                                 \
            TLS-ECDHE-ECDSA-WITH-NULL-SHA           \
            TLS-ECDHE-ECDSA-WITH-RC4-128-SHA        \
            TLS-ECDHE-ECDSA-WITH-3DES-EDE-CBC-SHA   \
            TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA    \
            TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA    \
            "

        O_CIPHERS="                         \
            ECDHE-ECDSA-NULL-SHA            \
            ECDHE-ECDSA-RC4-SHA             \
            ECDHE-ECDSA-DES-CBC3-SHA        \
            ECDHE-ECDSA-AES128-SHA          \
            ECDHE-ECDSA-AES256-SHA          \
            "

        if [ "$MODE" = "tls1_2" ];
        then
            P_CIPHERS="$P_CIPHERS                               \
                TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256         \
                TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384         \
                TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256         \
                TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384         \
                "

            O_CIPHERS="                         \
                ECDHE-ECDSA-AES128-SHA256       \
                ECDHE-ECDSA-AES256-SHA384       \
                ECDHE-ECDSA-AES128-GCM-SHA256   \
                ECDHE-ECDSA-AES256-GCM-SHA384   \
                "
        fi

        ;;

    "RSA")

        P_SERVER_ARGS="$P_SERVER_BASE crt_file=data_files/server1.crt key_file=data_files/server1.key"
        P_CLIENT_ARGS="$P_CLIENT_BASE crt_file=data_files/server2.crt key_file=data_files/server2.key"
        O_SERVER_ARGS="$O_SERVER_BASE -cert data_files/server1.crt -key data_files/server1.key"
        O_CLIENT_ARGS="$O_CLIENT_BASE -cert data_files/server2.crt -key data_files/server2.key"

        P_CIPHERS="                                 \
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
            TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA      \
            TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA      \
            TLS-ECDHE-RSA-WITH-3DES-EDE-CBC-SHA     \
            TLS-ECDHE-RSA-WITH-RC4-128-SHA          \
            TLS-ECDHE-RSA-WITH-NULL-SHA             \
            "

        O_CIPHERS="                         \
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
            ECDHE-RSA-AES256-SHA            \
            ECDHE-RSA-AES128-SHA            \
            ECDHE-RSA-DES-CBC3-SHA          \
            ECDHE-RSA-RC4-SHA               \
            ECDHE-RSA-NULL-SHA              \
            "

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

        P_SERVER_ARGS="$P_SERVER_BASE psk=6162636465666768696a6b6c6d6e6f70"
        P_CLIENT_ARGS="$P_CLIENT_BASE psk=6162636465666768696a6b6c6d6e6f70"
        O_SERVER_ARGS="$O_SERVER_BASE -psk 6162636465666768696a6b6c6d6e6f70"
        O_CLIENT_ARGS="$O_CLIENT_BASE -psk 6162636465666768696a6b6c6d6e6f70"

        P_CIPHERS="                                 \
            TLS-PSK-WITH-RC4-128-SHA                \
            TLS-PSK-WITH-3DES-EDE-CBC-SHA           \
            TLS-PSK-WITH-AES-128-CBC-SHA            \
            TLS-PSK-WITH-AES-256-CBC-SHA            \
            "

        O_CIPHERS="                         \
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


log "$OPENSSL s_server -cert data_files/server2.crt -key data_files/server2.key -www -quiet -cipher NULL,ALL $O_SERVER_ARGS -$MODE"
$OPENSSL s_server -cert data_files/server2.crt -key data_files/server2.key -www -quiet -cipher NULL,ALL $O_SERVER_ARGS -$MODE >/dev/null 2>&1 &
PROCESS_ID=$!

sleep 1

for i in $P_CIPHERS;
do
    let "tests++"
    log "../programs/ssl/ssl_client2 $P_CLIENT_ARGS force_ciphersuite=$i force_version=$MODE"
    RESULT="$( ../programs/ssl/ssl_client2 $P_CLIENT_ARGS force_ciphersuite=$i force_version=$MODE )"
    EXIT=$?
    echo -n "OpenSSL Server - PolarSSL Client - $i : $EXIT - "
    if [ "$EXIT" = "2" ];
    then
        echo Ciphersuite not supported in client
        let "skipped++"
    elif [ "$EXIT" != "0" ];
    then
        echo Failed
        echo $RESULT
        let "failed++"
    else
        echo Success
    fi
done
kill $PROCESS_ID
wait $PROCESS_ID 2>/dev/null

log "../programs/ssl/ssl_server2 $P_SERVER_ARGS force_version=$MODE > /dev/null"
../programs/ssl/ssl_server2 $P_SERVER_ARGS force_version=$MODE > /dev/null &
PROCESS_ID=$!

sleep 1

for i in $O_CIPHERS;
do
    let "tests++"
    log "$OPENSSL s_client -$MODE -cipher $i $O_CLIENT_ARGS"
    RESULT="$( ( echo -e 'GET HTTP/1.0'; echo; sleep 1 ) | $OPENSSL s_client -$MODE -cipher $i $O_CLIENT_ARGS 2>&1 )"
    EXIT=$?
    echo -n "PolarSSL Server - OpenSSL Client - $i : $EXIT - "

    if [ "$EXIT" != "0" ];
    then
        SUPPORTED="$( echo $RESULT | grep 'Cipher is (NONE)' )"
        if [ "X$SUPPORTED" != "X" ]
        then
            echo "Ciphersuite not supported in server"
            let "skipped++"
        else
            echo Failed
            echo ../programs/ssl/ssl_server2 $P_SERVER_ARGS 
            echo $OPENSSL s_client -$MODE -cipher $i $O_CLIENT_ARGS 
            echo $RESULT
            let "failed++"
        fi
    else
        echo Success
    fi
done

kill $PROCESS_ID
wait $PROCESS_ID 2>/dev/null

log "../programs/ssl/ssl_server2 $P_SERVER_ARGS force_version=$MODE"
../programs/ssl/ssl_server2 $P_SERVER_ARGS force_version=$MODE > /dev/null &
PROCESS_ID=$!

sleep 1

# Add ciphersuites supported by PolarSSL only

case $TYPE in

    "ECDSA")

        if [ "$MODE" = "tls1_2" ];
        then
            P_CIPHERS="$P_CIPHERS                               \
                TLS-ECDHE-ECDSA-WITH-CAMELLIA-128-CBC-SHA256    \
                TLS-ECDHE-ECDSA-WITH-CAMELLIA-256-CBC-SHA384    \
                "
        fi

        ;;

    "RSA")

        if [ "$MODE" = "tls1_2" ];
        then
            P_CIPHERS="$P_CIPHERS                           \
                TLS-RSA-WITH-CAMELLIA-128-CBC-SHA256        \
                TLS-RSA-WITH-CAMELLIA-256-CBC-SHA256        \
                TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA256    \
                TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA256    \
                TLS-ECDHE-RSA-WITH-CAMELLIA-128-CBC-SHA256  \
                TLS-ECDHE-RSA-WITH-CAMELLIA-256-CBC-SHA384  \
                TLS-ECDHE-RSA-WITH-CAMELLIA-128-GCM-SHA256      \
                TLS-ECDHE-RSA-WITH-CAMELLIA-256-GCM-SHA384      \
                TLS-DHE-RSA-WITH-CAMELLIA-128-GCM-SHA256    \
                TLS-DHE-RSA-WITH-CAMELLIA-256-GCM-SHA384    \
                TLS-RSA-WITH-CAMELLIA-128-GCM-SHA256        \
                TLS-RSA-WITH-CAMELLIA-256-GCM-SHA384        \
                "
        fi

        ;;

    "PSK")

        P_CIPHERS="$P_CIPHERS                        \
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
            "


        if [ "$MODE" != "ssl3" ];
        then
            P_CIPHERS="$P_CIPHERS                       \
                TLS-ECDHE-PSK-WITH-AES-256-CBC-SHA      \
                TLS-ECDHE-PSK-WITH-AES-128-CBC-SHA      \
                TLS-ECDHE-PSK-WITH-3DES-EDE-CBC-SHA     \
                TLS-ECDHE-PSK-WITH-RC4-128-SHA          \
                TLS-ECDHE-PSK-WITH-NULL-SHA             \
                "
        fi

        if [ "$MODE" = "tls1_2" ];
        then
            P_CIPHERS="$P_CIPHERS                        \
                TLS-PSK-WITH-AES-128-CBC-SHA256          \
                TLS-PSK-WITH-AES-256-CBC-SHA384          \
                TLS-DHE-PSK-WITH-AES-128-CBC-SHA256      \
                TLS-DHE-PSK-WITH-AES-256-CBC-SHA384      \
                TLS-PSK-WITH-AES-128-GCM-SHA256          \
                TLS-PSK-WITH-AES-256-GCM-SHA384          \
                TLS-DHE-PSK-WITH-AES-128-GCM-SHA256      \
                TLS-DHE-PSK-WITH-AES-256-GCM-SHA384      \
                TLS-PSK-WITH-NULL-SHA256                 \
                TLS-PSK-WITH-NULL-SHA384                 \
                TLS-DHE-PSK-WITH-NULL-SHA256             \
                TLS-DHE-PSK-WITH-NULL-SHA384             \
                TLS-PSK-WITH-CAMELLIA-128-CBC-SHA256     \
                TLS-PSK-WITH-CAMELLIA-256-CBC-SHA384     \
                TLS-RSA-PSK-WITH-CAMELLIA-128-GCM-SHA256 \
                TLS-RSA-PSK-WITH-CAMELLIA-256-GCM-SHA384 \
                TLS-PSK-WITH-CAMELLIA-128-GCM-SHA256     \
                TLS-PSK-WITH-CAMELLIA-256-GCM-SHA384     \
                TLS-DHE-PSK-WITH-CAMELLIA-128-GCM-SHA256 \
                TLS-DHE-PSK-WITH-CAMELLIA-256-GCM-SHA384 \
                TLS-DHE-PSK-WITH-CAMELLIA-128-CBC-SHA256 \
                TLS-DHE-PSK-WITH-CAMELLIA-256-CBC-SHA384 \
                TLS-RSA-PSK-WITH-AES-256-CBC-SHA384         \
                TLS-RSA-PSK-WITH-AES-256-GCM-SHA384         \
                TLS-RSA-PSK-WITH-CAMELLIA-256-CBC-SHA384    \
                TLS-RSA-PSK-WITH-AES-128-CBC-SHA256         \
                TLS-RSA-PSK-WITH-AES-128-GCM-SHA256         \
                TLS-RSA-PSK-WITH-CAMELLIA-128-CBC-SHA256    \
                TLS-RSA-WITH-NULL-SHA256                    \
                TLS-ECDHE-PSK-WITH-AES-256-CBC-SHA384       \
                TLS-ECDHE-PSK-WITH-CAMELLIA-256-CBC-SHA384  \
                TLS-ECDHE-PSK-WITH-AES-128-CBC-SHA256       \
                TLS-ECDHE-PSK-WITH-CAMELLIA-128-CBC-SHA256  \
                TLS-ECDHE-PSK-WITH-NULL-SHA384              \
                TLS-ECDHE-PSK-WITH-NULL-SHA256              \
                "
        fi

esac

# Filter ciphersuites
if [ "X" != "X$FILTER" ];
then
  O_CIPHERS=$( filter "$O_CIPHERS" "$FILTER" )
  P_CIPHERS=$( filter "$P_CIPHERS" "$FILTER" )
fi

for i in $P_CIPHERS;
do
    let "tests++"
    log "../programs/ssl/ssl_client2 force_ciphersuite=$i force_version=$MODE $P_CLIENT_ARGS"
    RESULT="$( ../programs/ssl/ssl_client2 force_ciphersuite=$i force_version=$MODE $P_CLIENT_ARGS )"
    EXIT=$?
    echo -n "PolarSSL Server - PolarSSL Client - $i : $EXIT - "
    if [ "$EXIT" = "2" ];
    then
        echo Ciphersuite not supported in client
        let "skipped++"
    elif [ "$EXIT" != "0" ];
    then
        echo Failed
        echo $RESULT
        let "failed++"
    else
        echo Success
    fi
done
kill $PROCESS_ID
wait $PROCESS_ID 2>/dev/null

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
