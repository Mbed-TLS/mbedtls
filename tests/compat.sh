killall -q openssl ssl_server

MODES="ssl3 tls1 tls1_1 tls1_2"
#VERIFY="YES"
VERIFY=""

if [ "X$VERIFY" = "XYES" ];
then
    P_CLIENT_ARGS="crt_file=data_files/server2.crt key_file=data_files/server2.key"
    O_SERVER_ARGS="-verify 10 -CAfile data_files/test-ca.crt"
fi

for MODE in $MODES;
do
echo "Running for $MODE"
echo "-----------"

P_CIPHERS="                             \
    SSL-EDH-RSA-AES-128-SHA             \
    SSL-EDH-RSA-AES-256-SHA             \
    SSL-EDH-RSA-CAMELLIA-128-SHA        \
    SSL-EDH-RSA-CAMELLIA-256-SHA        \
    SSL-EDH-RSA-DES-168-SHA             \
    SSL-RSA-AES-256-SHA                 \
    SSL-RSA-CAMELLIA-256-SHA            \
    SSL-RSA-AES-128-SHA                 \
    SSL-RSA-CAMELLIA-128-SHA            \
    SSL-RSA-DES-168-SHA                 \
    SSL-RSA-RC4-128-SHA                 \
    SSL-RSA-RC4-128-MD5                 \
    SSL-RSA-NULL-MD5                    \
    SSL-RSA-NULL-SHA                    \
    SSL-RSA-DES-SHA                     \
    SSL-EDH-RSA-DES-SHA                 \
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
    "

if [ "$MODE" = "tls1_2" ];
then
    P_CIPHERS="$P_CIPHERS               \
        SSL-RSA-NULL-SHA256             \
        SSL-RSA-AES-128-SHA256          \
        SSL-EDH-RSA-AES-128-SHA256      \
        SSL-RSA-AES-256-SHA256          \
        SSL-EDH-RSA-AES-256-SHA256      \
        SSL-RSA-AES-128-GCM-SHA256      \
        SSL-EDH-RSA-AES-128-GCM-SHA256  \
        SSL-RSA-AES-256-GCM-SHA384      \
        SSL-EDH-RSA-AES-256-GCM-SHA384  \
        "

    O_CIPHERS="$O_CIPHERS           \
        NULL-SHA256                 \
        AES128-SHA256               \
        DHE-RSA-AES128-SHA256       \
        AES256-SHA256               \
        DHE-RSA-AES256-SHA256       \
        AES128-GCM-SHA256           \
        DHE-RSA-AES128-GCM-SHA256   \
        AES256-GCM-SHA384           \
        DHE-RSA-AES256-GCM-SHA384   \
        "
fi

openssl s_server -cert data_files/server2.crt -key data_files/server2.key -www -quiet -cipher NULL,ALL $O_SERVER_ARGS -$MODE &
PROCESS_ID=$!

sleep 1

for i in $P_CIPHERS;
do
    RESULT="$( ../programs/ssl/ssl_client2 $P_CLIENT_ARGS force_ciphersuite=$i )"
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

../programs/ssl/ssl_server > /dev/null &
PROCESS_ID=$!

sleep 1

for i in $O_CIPHERS;
do
    RESULT="$( ( echo -e 'GET HTTP/1.0'; echo; sleep 1 ) | openssl s_client -$MODE -cipher $i 2>&1)"
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
            echo $RESULT
        fi
    else
        echo Success
    fi
done

kill $PROCESS_ID

../programs/ssl/ssl_server > /dev/null &
PROCESS_ID=$!

sleep 1

# OpenSSL does not support RFC5246 Camellia ciphers with SHA256
# Add for PolarSSL only test, which does support them.
#
if [ "$MODE" = "tls1_2" ];
then
    P_CIPHERS="$P_CIPHERS               \
        SSL-RSA-CAMELLIA-128-SHA256     \
        SSL-EDH-RSA-CAMELLIA-128-SHA256 \
        SSL-RSA-CAMELLIA-256-SHA256     \
        SSL-EDH-RSA-CAMELLIA-256-SHA256 \
        "
fi

for i in $P_CIPHERS;
do
    RESULT="$( ../programs/ssl/ssl_client2 force_ciphersuite=$i )"
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

done

