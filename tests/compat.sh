#!/bin/bash

killall -q openssl ssl_server ssl_server2

MODES="ssl3 tls1 tls1_1 tls1_2"
VERIFIES="NO YES"
TYPES="RSA PSK"
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

for VERIFY in $VERIFIES;
do

if [ "X$VERIFY" = "XYES" ];
then
    P_SERVER_ARGS="ca_file=data_files/test-ca.crt auth_mode=required"
    P_CLIENT_ARGS="ca_file=data_files/test-ca.crt"
    O_SERVER_ARGS="-CAfile data_files/test-ca.crt -verify 10"
    O_CLIENT_ARGS="-CAfile data_files/test-ca.crt"
else
    P_SERVER_ARGS=""
    P_CLIENT_ARGS=""
    O_SERVER_ARGS=""
    O_CLIENT_ARGS=""
fi


for MODE in $MODES;
do
echo "Running for $MODE (Verify: $VERIFY)"
echo "-----------"

for TYPE in $TYPES;
do

case $TYPE in

    "RSA")

        P_SERVER_ARGS="$P_SERVER_ARGS crt_file=data_files/server1.crt key_file=data_files/server1.key"
        P_CLIENT_ARGS="$P_CLIENT_ARGS crt_file=data_files/server2.crt key_file=data_files/server2.key"
        O_SERVER_ARGS="$O_SERVER_ARGS -cert data_files/server1.crt -key data_files/server1.key"
        O_CLIENT_ARGS="$O_CLIENT_ARGS -cert data_files/server2.crt -key data_files/server2.key"

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
            TLS-RSA-EXPORT-WITH-RC4-40-MD5          \
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
            EXP-RC4-MD5                     \
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

        P_SERVER_ARGS="$P_SERVER_ARGS psk=6162636465666768696a6b6c6d6e6f70"
        P_CLIENT_ARGS="$P_CLIENT_ARGS psk=6162636465666768696a6b6c6d6e6f70"
        O_SERVER_ARGS="$O_SERVER_ARGS -psk 6162636465666768696a6b6c6d6e6f70"
        O_CLIENT_ARGS="$O_CLIENT_ARGS -psk 6162636465666768696a6b6c6d6e6f70"

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

# Filter ciphersuites
if [ "X" != "X$FILTER" ];
then
  O_CIPHERS=$( filter "$O_CIPHERS" "$FILTER" )
  P_CIPHERS=$( filter "$P_CIPHERS" "$FILTER" )
fi


log "$OPENSSL s_server -cert data_files/server2.crt -key data_files/server2.key -www -quiet -cipher NULL,ALL $O_SERVER_ARGS -$MODE"
$OPENSSL s_server -cert data_files/server2.crt -key data_files/server2.key -www -quiet -cipher NULL,ALL $O_SERVER_ARGS -$MODE &
PROCESS_ID=$!

sleep 1

for i in $P_CIPHERS;
do
    log "../programs/ssl/ssl_client2 $P_CLIENT_ARGS force_ciphersuite=$i force_version=$MODE"
    RESULT="$( ../programs/ssl/ssl_client2 $P_CLIENT_ARGS force_ciphersuite=$i force_version=$MODE )"
    EXIT=$?
    echo -n "OpenSSL Server - PolarSSL Client - $i : $EXIT - "
    if [ "$EXIT" = "2" ];
    then
        echo Ciphersuite not supported in client
    elif [ "$EXIT" != "0" ];
    then
        echo Failed
        echo $RESULT
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
        else
            echo Failed
            echo ../programs/ssl/ssl_server2 $P_SERVER_ARGS 
            echo $OPENSSL s_client -$MODE -cipher $i $O_CLIENT_ARGS 
            echo $RESULT
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

    "RSA")

        if [ "$MODE" = "tls1_2" ];
        then
            P_CIPHERS="$P_CIPHERS                        \
                TLS-RSA-WITH-CAMELLIA-128-CBC-SHA256     \
                TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA256 \
                TLS-RSA-WITH-CAMELLIA-256-CBC-SHA256     \
                TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA256 \
                TLS-ECDHE-RSA-WITH-CAMELLIA-128-CBC-SHA256 \
                TLS-ECDHE-RSA-WITH-CAMELLIA-256-CBC-SHA384 \
                "
        fi

        ;;

    "PSK")

        P_CIPHERS="$P_CIPHERS                        \
            TLS-DHE-PSK-WITH-RC4-128-SHA             \
            TLS-DHE-PSK-WITH-3DES-EDE-CBC-SHA        \
            TLS-DHE-PSK-WITH-AES-128-CBC-SHA         \
            TLS-DHE-PSK-WITH-AES-256-CBC-SHA         \
            TLS-PSK-WITH-NULL-SHA                    \
            TLS-DHE-PSK-WITH-NULL-SHA                \
            "

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
                TLS-DHE-PSK-WITH-CAMELLIA-128-CBC-SHA256 \
                TLS-DHE-PSK-WITH-CAMELLIA-256-CBC-SHA384 \
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
    log "../programs/ssl/ssl_client2 force_ciphersuite=$i force_version=$MODE $P_CLIENT_ARGS"
    RESULT="$( ../programs/ssl/ssl_client2 force_ciphersuite=$i force_version=$MODE $P_CLIENT_ARGS )"
    EXIT=$?
    echo -n "PolarSSL Server - PolarSSL Client - $i : $EXIT - "
    if [ "$EXIT" = "2" ];
    then
        echo Ciphersuite not supported in client
    elif [ "$EXIT" != "0" ];
    then
        echo Failed
        echo $RESULT
    else
        echo Success
    fi
done
kill $PROCESS_ID
wait $PROCESS_ID 2>/dev/null

done
done
done
