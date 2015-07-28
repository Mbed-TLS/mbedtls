/*
 *  Hello world example of a TLS client: fetch an HTTPS page
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#if !defined(TARGET_LIKE_MBED)

#include <stdio.h>

int main() {
    printf("this program only works on mbed OS\n");
    return 0;
}

#else

/** \file main.cpp
 *  \brief An example TLS Client application
 *  This application sends an HTTPS request to developer.mbed.org and searches for a string in
 *  the result.
 *
 *  This example is implemented as a logic class (HelloHTTPS) wrapping a TCP socket.
 *  The logic class handles all events, leaving the main loop to just check if the process
 *  has finished.
 */

/* Change to a number between 1 and 4 to debug the TLS connection */
#define DEBUG_LEVEL 0

/* Change to 1 to skip certificate verification (UNSAFE, for debug only!) */
#define UNSAFE 0

#include "mbed.h"
#include <mbed-net-lwip-eth/EthernetInterface.h>
#include <mbed-net-sockets/TCPStream.h>

#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#if DEBUG_LEVEL > 0
#include "mbedtls/debug.h"
#endif

#include "lwipv4_init.h"

namespace {
const char *HTTPS_SERVER_NAME = "developer.mbed.org";
const int HTTPS_SERVER_PORT = 443;
const int RECV_BUFFER_SIZE = 600;

const char HTTPS_PATH[] = "/media/uploads/mbed_official/hello.txt";
const size_t HTTPS_PATH_LEN = sizeof(HTTPS_PATH) - 1;

/* Test related data */
const char *HTTPS_OK_STR = "200 OK";
const char *HTTPS_HELLO_STR = "Hello world!";

/* personalization string for the drbg */
const char *DRBG_PERS = "mbed TLS helloword client";

/* List of trusted root CA certificates
 * currently just Verisign since it's the root used by developer.mbed.org
 * If you want to trust more that one root, just concatenate them.
 */
const char SSL_CA_PEM[] =
"-----BEGIN CERTIFICATE-----\n"
"MIIDdTCCAl2gAwIBAgILBAAAAAABFUtaw5QwDQYJKoZIhvcNAQEFBQAwVzELMAkG\n"
"A1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExEDAOBgNVBAsTB1Jv\n"
"b3QgQ0ExGzAZBgNVBAMTEkdsb2JhbFNpZ24gUm9vdCBDQTAeFw05ODA5MDExMjAw\n"
"MDBaFw0yODAxMjgxMjAwMDBaMFcxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i\n"
"YWxTaWduIG52LXNhMRAwDgYDVQQLEwdSb290IENBMRswGQYDVQQDExJHbG9iYWxT\n"
"aWduIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDaDuaZ\n"
"jc6j40+Kfvvxi4Mla+pIH/EqsLmVEQS98GPR4mdmzxzdzxtIK+6NiY6arymAZavp\n"
"xy0Sy6scTHAHoT0KMM0VjU/43dSMUBUc71DuxC73/OlS8pF94G3VNTCOXkNz8kHp\n"
"1Wrjsok6Vjk4bwY8iGlbKk3Fp1S4bInMm/k8yuX9ifUSPJJ4ltbcdG6TRGHRjcdG\n"
"snUOhugZitVtbNV4FpWi6cgKOOvyJBNPc1STE4U6G7weNLWLBYy5d4ux2x8gkasJ\n"
"U26Qzns3dLlwR5EiUWMWea6xrkEmCMgZK9FGqkjWZCrXgzT/LCrBbBlDSgeF59N8\n"
"9iFo7+ryUp9/k5DPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8E\n"
"BTADAQH/MB0GA1UdDgQWBBRge2YaRQ2XyolQL30EzTSo//z9SzANBgkqhkiG9w0B\n"
"AQUFAAOCAQEA1nPnfE920I2/7LqivjTFKDK1fPxsnCwrvQmeU79rXqoRSLblCKOz\n"
"yj1hTdNGCbM+w6DjY1Ub8rrvrTnhQ7k4o+YviiY776BQVvnGCv04zcQLcFGUl5gE\n"
"38NflNUVyRRBnMRddWQVDf9VMOyGj/8N7yy5Y0b2qvzfvGn9LhJIZJrglfCm7ymP\n"
"AbEVtQwdpf5pLGkkeB6zpxxxYu7KyJesF12KwvhHhm4qxFYxldBniYUr+WymXUad\n"
"DKqC5JlR3XC321Y9YeRq4VzW9v493kHMB65jUr9TU/Qr6cf9tveCX4XSQRjbgbME\n"
"HMUfpIBvFSDJ3gyICh3WZlXi/EjJKSZp4A==\n"
"-----END CERTIFICATE-----\n";
}

/**
 * \brief HelloHTTPS implements the logic for fetching a file from a webserver
 * using a TCP socket and parsing the result.
 */
class HelloHTTPS {
public:
    /**
     * HelloHTTPS Constructor
     * Initializes the TCP socket, sets up event handlers and flags.
     *
     * Note that CThunk is used for event handlers.  This will be changed to a C++
     * function pointer in an upcoming release.
     *
     *
     * @param[in] domain The domain name to fetch from
     * @param[in] port The port of the HTTPS server
     */
    HelloHTTPS(const char * domain, const uint16_t port) :
            _stream(SOCKET_STACK_LWIP_IPV4), _domain(domain), _port(port)
    {

        _error = false;
        _gothello = false;
        _got200 = false;
        _bpos = 0;
        _request_sent = 0;
        _stream.open(SOCKET_AF_INET4);

        mbedtls_entropy_init(&_entropy);
        mbedtls_ctr_drbg_init(&_ctr_drbg);
        mbedtls_x509_crt_init(&_cacert);
        mbedtls_ssl_init(&_ssl);
        mbedtls_ssl_config_init(&_ssl_conf);
    }
    /**
     * Initiate the test.
     *
     * Starts by clearing test flags, then resolves the address with DNS.
     *
     * @param[in] path The path of the file to fetch from the HTTPS server
     * @return SOCKET_ERROR_NONE on success, or an error code on failure
     */
    socket_error_t startTest(const char *path) {
        /* Initialize the flags */
        _got200 = false;
        _gothello = false;
        _error = false;
        _disconnected = false;
        _request_sent = false;
        /* Fill the request buffer */
        _bpos = snprintf(_buffer, sizeof(_buffer) - 1, "GET %s HTTP/1.1\nHost: %s\n\n", path, HTTPS_SERVER_NAME);

        /*
         * Initialize TLS-related stuf.
         */
        int ret;
        if ((ret = mbedtls_ctr_drbg_seed(&_ctr_drbg, mbedtls_entropy_func, &_entropy,
                          (const unsigned char *) DRBG_PERS,
                          sizeof (DRBG_PERS))) != 0) {
            print_mbedtls_error("mbedtls_crt_drbg_init", ret);
            return SOCKET_ERROR_UNKNOWN;
        }

        if ((ret = mbedtls_x509_crt_parse(&_cacert, (const unsigned char *) SSL_CA_PEM,
                           sizeof (SSL_CA_PEM))) != 0) {
            print_mbedtls_error("mbedtls_x509_crt_parse", ret);
            return SOCKET_ERROR_UNKNOWN;
        }

        if ((ret = mbedtls_ssl_config_defaults(&_ssl_conf,
                        MBEDTLS_SSL_IS_CLIENT,
                        MBEDTLS_SSL_TRANSPORT_STREAM,
                        MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
            print_mbedtls_error("mbedtls_ssl_config_defaults", ret);
            return SOCKET_ERROR_UNKNOWN;
        }

        mbedtls_ssl_conf_ca_chain(&_ssl_conf, &_cacert, NULL);
        mbedtls_ssl_conf_rng(&_ssl_conf, mbedtls_ctr_drbg_random, &_ctr_drbg);

#if UNSAFE
        mbedtls_ssl_conf_authmode(&_ssl_conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
#endif

#if DEBUG_LEVEL > 0
        mbedtls_ssl_conf_verify(&_ssl_conf, my_verify, NULL);
        mbedtls_ssl_conf_dbg(&_ssl_conf, my_debug, NULL);
        mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif

        if ((ret = mbedtls_ssl_setup(&_ssl, &_ssl_conf)) != 0) {
            print_mbedtls_error("mbedtls_ssl_setup", ret);
            return SOCKET_ERROR_UNKNOWN;
        }

        mbedtls_ssl_set_hostname(&_ssl, HTTPS_SERVER_NAME);

        mbedtls_ssl_set_bio(&_ssl, static_cast<void *>(&_stream),
                                   ssl_send, ssl_recv, NULL );


        /* Connect to the server */
        printf("Connecting to %s:%d\r\n", _domain, _port);
        /* Resolve the domain name: */
        socket_error_t err = _stream.resolve(_domain, handler_t(this, &HelloHTTPS::onDNS));
        return err;
    }
    /**
     * Check if the test has completed.
     * @return Returns true if done, false otherwise.
     */
    bool done() {
        return _error || (_got200 && _gothello);
    }
    /**
     * Check if there was an error
     * @return Returns true if there was an error, false otherwise.
     */
    bool error() {
        return _error;
    }
    /**
     * Closes the TCP socket
     */
    void close() {
        _stream.close();
        while (!_disconnected)
            __WFI();
    }
protected:
    /**
     * Helper for pretty-printing mbed TLS error codes
     */
    static void print_mbedtls_error(const char *name, int err) {
        char buf[128];
        mbedtls_strerror(err, buf, sizeof (buf));
        printf("%s() failed: -0x%04x (%d): %s\r\n", name, -err, err, buf);
    }

#if DEBUG_LEVEL > 0
    /**
     * Debug callback for mbed TLS
     * Just prints on the USB serial port
     */
    static void my_debug(void *ctx, int level, const char *str)
    {
        (void) ctx;
        (void) level;

        printf("%s", str);
    }

    /**
     * Certificate verification callback for mbed TLS
     * Here we only use it to display information on each cert in the chain
     */
    static int my_verify(void *data, mbedtls_x509_crt *crt, int depth, int *flags)
    {
        char buf[1024];
        (void) data;

        printf("\nVerifying certificate at depth %d:\n", depth);
        mbedtls_x509_crt_info(buf, sizeof (buf) - 1, "  ", crt);
        printf("%s", buf);

        if (*flags == 0)
            printf("No verification issue for this certificate\n");
        else
        {
            mbedtls_x509_crt_verify_info(buf, sizeof (buf), "  ! ", *flags);
            printf("%s\n", buf);
        }

        return 0;
    }
#endif

    /**
     * Receive callback for mbed TLS
     */
    static int ssl_recv(void *ctx, unsigned char *buf, size_t len) {
        mbed::TCPStream *stream = static_cast<mbed::TCPStream *>(ctx);
        socket_error_t err = stream->recv(buf, &len);

        if (err == SOCKET_ERROR_NONE) {
            return static_cast<int>(len);
        } else if (err == SOCKET_ERROR_WOULD_BLOCK) {
            return MBEDTLS_ERR_SSL_WANT_READ;
        } else {
            return -1;
        }
    }

    /**
     * Send callback for mbed TLS
     */
    static int ssl_send(void *ctx, const unsigned char *buf, size_t len) {
        mbed::TCPStream *stream = static_cast<mbed::TCPStream *>(ctx);

        socket_error_t err = stream->send(buf, len);

        if (err == SOCKET_ERROR_NONE) {
            return static_cast<int>(len);
        } else if (err == SOCKET_ERROR_WOULD_BLOCK) {
            return MBEDTLS_ERR_SSL_WANT_WRITE;
        } else {
            return -1;
        }
    }

    /**
     * On Connect handler
     * Sends the request which was generated in startTest
     */
    void onConnect(socket_error_t err) {
        (void) err;

        _stream.setOnReadable(handler_t(this, &HelloHTTPS::onReceive));
        _stream.setOnDisconnect(handler_t(this, &HelloHTTPS::onDisconnect));

        /* Start the handshake, the rest will be done in onReceive() */
        int ret = mbedtls_ssl_handshake(&_ssl);
        if (ret < 0) {
            if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
                ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                print_mbedtls_error("mbedtls_ssl_handshake", ret);
                _error = true;
            }
            return;
        }
    }
    /**
     * On Receive handler
     * Parses the response from the server, to check for the HTTPS 200 status code and the expected response ("Hello World!")
     */
    void onReceive(socket_error_t err) {
        (void) err;

        if (_error)
            return;

        /* Send request if not done yet */
        if (!_request_sent) {
            int ret = mbedtls_ssl_write(&_ssl, (const unsigned char *) _buffer, _bpos);
            if (ret < 0) {
                if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
                    ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                    print_mbedtls_error("mbedtls_ssl_write", ret);
                    _error = true;
                }
                return;
            }

            /* If we get here, the request was sent */
            _request_sent = 1;

            /* It also means the handshake is done, time to print info */
            printf("TLS connection to %s established\r\n", HTTPS_SERVER_NAME);
            {
                char buf[1024];
                mbedtls_x509_crt_info(buf, sizeof(buf), "\r    ",
                        mbedtls_ssl_get_peer_cert(&_ssl));
                printf("Server certificate:\r\n%s\r", buf);

#if defined(UNSAFE)
                uint32_t flags = mbedtls_ssl_get_verify_result(&_ssl);
                if( flags != 0 )
                {
                    mbedtls_x509_crt_verify_info(buf, sizeof (buf), "\r  ! ", flags);
                    printf("Certificate verification failed:\r\n%s\r\r\n", buf);
                }
                else
#endif
                    printf("Certificate verification passed\r\n\r\n");
            }
        }

        /* Read data out of the socket */
        int ret = mbedtls_ssl_read(&_ssl, (unsigned char *) _buffer, sizeof(_buffer));
        if (ret < 0) {
            if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
                ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                    print_mbedtls_error("mbedtls_ssl_read", ret);
                _error = true;
            }
            return;
        }
        _bpos = static_cast<size_t>(ret);

        _buffer[_bpos] = 0;

        /* Check each of the flags */
        _got200 = _got200 || strstr(_buffer, HTTPS_OK_STR) != NULL;
        _gothello = _gothello || strstr(_buffer, HTTPS_HELLO_STR) != NULL;

        /* Print status messages */
        printf("HTTPS: Received %d chars from server\r\n", _bpos);
        printf("HTTPS: Received 200 OK status ... %s\r\n", _got200 ? "[OK]" : "[FAIL]");
        printf("HTTPS: Received '%s' status ... %s\r\n", HTTPS_HELLO_STR, _gothello ? "[OK]" : "[FAIL]");
        printf("HTTPS: Received message:\r\n\r\n");
        printf("%s", _buffer);
        _error = !(_got200 && _gothello);
    }
    /**
     * On DNS Handler
     * Reads the address returned by DNS, then starts the connect process.
     */
    void onDNS(socket_error_t err) {
        socket_event_t *e = _stream.getEvent();
        /* Check that the result is a valid DNS response */
        if (socket_addr_is_any(&e->i.d.addr)) {
            /* Could not find DNS entry */
            _error = true;
            printf("Could not find DNS entry for %s", HTTPS_SERVER_NAME);
            return;
        } else {
            /* Start connecting to the remote host */
            _remoteAddr.setAddr(&e->i.d.addr);
            err = _stream.connect(&_remoteAddr, _port, handler_t(this, &HelloHTTPS::onConnect));

            if (err != SOCKET_ERROR_NONE) {
                _error = true;
            }
        }
    }
    void onDisconnect(socket_error_t err) {
        (void) err;
        _disconnected = true;
    }

protected:
    mbed::TCPStream _stream;        /**< The TCP Socket */
    const char *_domain;            /**< The domain name of the HTTPS server */
    const uint16_t _port;           /**< The HTTPS server port */
    char _buffer[RECV_BUFFER_SIZE]; /**< The response buffer */
    size_t _bpos;                   /**< The current offset in the response buffer */
    mbed::SocketAddr _remoteAddr;   /**< The remote address */
    volatile bool _got200;          /**< Status flag for HTTPS 200 */
    volatile bool _gothello;        /**< Status flag for finding the test string */
    volatile bool _error;           /**< Status flag for an error */
    volatile bool _disconnected;
    volatile bool _request_sent;

    mbedtls_entropy_context _entropy;
    mbedtls_ctr_drbg_context _ctr_drbg;
    mbedtls_x509_crt _cacert;
    mbedtls_ssl_context _ssl;
    mbedtls_ssl_config _ssl_conf;
};

/**
 * The main loop of the HTTPS Hello World test
 */
int example_client() {
    EthernetInterface eth;
    /* Initialise with DHCP, connect, and start up the stack */
    eth.init();
    eth.connect();
    lwipv4_socket_init();

    printf("\r\n\r\n");
    printf("Client IP Address is %s\r\n", eth.getIPAddress());

    HelloHTTPS hello(HTTPS_SERVER_NAME, HTTPS_SERVER_PORT);
    socket_error_t rc = hello.startTest(HTTPS_PATH);
    if (rc != SOCKET_ERROR_NONE) {
        return 1;
    }
    while (!hello.done()) {
        __WFI();
    }
    if (hello.error()) {
        printf("Failed to fetch %s from %s:%d\r\n", HTTPS_PATH, HTTPS_SERVER_NAME, HTTPS_SERVER_PORT);
    }
    /* Shut down the socket before the ethernet interface */
    hello.close();
    eth.disconnect();
    return static_cast<int>(hello.error());
}

#include "mbed/test_env.h"

int main() {
    /* The default 9600 bps is too slow to print full TLS debug info and could
     * cause the other party to time out. Select a higher baud rate for
     * printf(), regardless of debug level for the sake of uniformity. */
    Serial pc(USBTX, USBRX);
    pc.baud(115200);

    MBED_HOSTTEST_TIMEOUT(120);
    MBED_HOSTTEST_SELECT(default);
    MBED_HOSTTEST_DESCRIPTION(mbed TLS example HTTPS client);
    MBED_HOSTTEST_START("MBEDTLS_EX_HTTPS_CLIENT");
    MBED_HOSTTEST_RESULT(example_client() == 0);
}

#endif /* TARGET_LIKE_MBED */
