killall -q openssl ssl_server

openssl s_server -cert data_files/server2.crt -key data_files/server2.key -www -quiet -cipher NULL,ALL &
PROCESS_ID=$!

sleep 1

CIPHERS="                               \
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

#    Not supported by OpenSSL: SSL-RSA-NULL-SHA256
for i in $CIPHERS;
do
    RESULT="$( ../programs/ssl/ssl_client2 force_ciphersuite=$i )"
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

CIPHERS="                           \
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

#    Not supported by OpenSSL: NULL-SHA256
for i in $CIPHERS;
do
    RESULT="$( ( echo -e 'GET HTTP/1.0'; echo; sleep 1 ) | openssl s_client -cipher $i 2>&1)"
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

CIPHERS="                               \
    SSL-RSA-RC4-128-SHA                 \
    SSL-RSA-NULL-MD5                    \
    SSL-EDH-RSA-AES-128-SHA             \
    SSL-EDH-RSA-AES-256-SHA             \
    SSL-EDH-RSA-CAMELLIA-128-SHA        \
    SSL-EDH-RSA-CAMELLIA-256-SHA        \
    SSL-EDH-RSA-DES-168-SHA             \
    SSL-RSA-NULL-SHA                    \
    SSL-RSA-AES-256-SHA                 \
    SSL-RSA-CAMELLIA-256-SHA            \
    SSL-RSA-AES-128-SHA                 \
    SSL-RSA-CAMELLIA-128-SHA            \
    SSL-RSA-DES-168-SHA                 \
    SSL-RSA-RC4-128-MD5                 \
    SSL-RSA-DES-SHA                     \
    SSL-EDH-RSA-DES-SHA                 \
    SSL-RSA-NULL-SHA256                 \
    "

for i in $CIPHERS;
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

