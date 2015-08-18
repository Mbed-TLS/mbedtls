# HTTPS file downloader (TLS client example)

This application downloads a file from an HTTPS server (mbed.org) and looks for a specific string in that file.

This example is implemented as a logic class (HelloHTTPS) wrapping a TCP socket and a TLS context. The logic class handles all events, leaving the main loop to just check if the process has finished.

## Pre-requisites

To build and run this example the requirements below are necessary:

* A computer with the following software installed:
  * [CMake](http://www.cmake.org/download/).
  * [yotta](https://github.com/ARMmbed/yotta). Please note that **yotta has its own set of dependencies**, listed in the [installation instructions](http://armmbed.github.io/yotta/#installing-on-windows).
  * [Python](https://www.python.org/downloads/).
  * [ARM GCC toolchain](https://launchpad.net/gcc-arm-embedded).
  * A serial terminal emulator (e.g. screen, pySerial, cu).
* An [FRDM-K64F](http://developer.mbed.org/platforms/FRDM-K64F/) development board, or another board that has an Ethernet port and is supported by mbed OS (in that case you'll have to substitute frdm-k64f-gcc with the appropriate target below).
* An Ethernet connection to the internet.
* An Ethernet cable.
* A micro-USB cable.
* If your OS is Windows, please follow the installation instructions [for the serial port driver](https://developer.mbed.org/handbook/Windows-serial-configuration).

## Getting started

1. Connect the FRDM-K64F to the internet using the ethernet cable.

2. Connect the FRDM-K64F to the computer with the micro-USB cable, being careful to use the micro-usb port labeled "OpenSDA".

3. Navigate to the mbedtls directory supplied with your release and open a terminal.

4. Set the yotta target:

    ```
    yotta target frdm-k64f-gcc
    ```

5. Build mbedtls and the examples. This will take a long time if it is the first time:

    ```
    $ yt build
    ```

6. Copy `build/frdm-k64f-gcc/test/mbedtls-test-example-tls-client.bin` to your mbed board and wait until the LED next to the USB port stops blinking.

7. Start the serial terminal emulator and connect to the virtual serial port presented by FRDM-K64F. For settings, use 115200 baud, 8N1, no flow control. **Warning:** for this example, the baud rate is not the default 9600, it is 115200.

8. Press the reset button on the board.

9. The output in the terminal window should look like:

    ```
    {timeout;120}}
    {{host_test_name;default}}
    {{description;mbed TLS example HTTPS client}}
    {{test_id;MBEDTLS_EX_HTTPS_CLIENT}}
    {{start}}


    Client IP Address is 192.168.0.2
    Connecting to developer.mbed.org:443
    developer.mbed.org address: 217.140.101.20
    TLS connection to developer.mbed.org established
    Server certificate:
        cert. version     : 3
        serial number     : 11:21:4E:4B:13:27:F0:89:21:FB:70:EC:3B:B5:73:5C:FF:B9
        issuer name       : C=BE, O=GlobalSign nv-sa, CN=GlobalSign Organization Validation CA - SHA256 - G2
        subject name      : C=GB, ST=Cambridgeshire, L=Cambridge, O=ARM Ltd, CN=*.mbed.com
        issued  on        : 2015-03-05 10:31:02
        expires on        : 2016-03-05 10:31:02
        signed using      : RSA with SHA-256
        RSA key size      : 2048 bits
        basic constraints : CA=false
        subject alt name  : *.mbed.com, *.mbed.org, mbed.org, mbed.com
        key usage         : Digital Signature, Key Encipherment
        ext key usage     : TLS Web Server Authentication, TLS Web Client Authentication
    Certificate verification passed

    HTTPS: Received 469 chars from server
    HTTPS: Received 200 OK status ... [OK]
    HTTPS: Received 'Hello world!' status ... [OK]
    HTTPS: Received message:

    HTTP/1.1 200 OK
    Server: nginx/1.7.10
    Date: Mon, 17 Aug 2015 11:46:19 GMT
    Content-Type: text/plain
    Content-Length: 14
    Connection: keep-alive
    Last-Modified: Fri, 27 Jul 2012 13:30:34 GMT
    Accept-Ranges: bytes
    Cache-Control: max-age=36000
    Expires: Mon, 17 Aug 2015 21:46:19 GMT
    X-Upstream-L3: 172.17.42.1:8080
    X-Upstream-L2: developer-sjc-cyan-1-nginx
    X-Upstream-L1-next-hop: 217.140.101.22:8001
    X-Upstream-L1: developer-sjc-cyan-border-nginx

    Hello world!
    {{success}}
    {{end}}
    ```

## Debugging the TLS connection

If you are experiencing problems with this example, you should first rule out network issues by making sure the [simple HTTP file downloader example](https://github.com/ARMmbed/mbed-example-network-private/tree/maste r/test/helloworld-tcpclient) for the TCP module works as expected. If not, please follow the debug instructions for this example.

To print out more debug information about the TLS connection, edit the file `source/main.cpp` and change the definition of `DEBUG_LEVEL` near the top of the file from 0 to a positive number:

* Level 1 only prints non-zero return codes from SSL functions and information about the full certificate chain being verified.

* Level 2 prints more information about internal state updates.

* Level 3 is intermediate.

* Level 4 (the maximum) includes full binary dumps of the packets.

If the TLS connection is failing with an error similar to:

    ```
    mbedtls_ssl_write() failed: -0x2700 (-9984): X509 - Certificate verification failed, e.g. CRL, CA or signature check failed
    Failed to fetch /media/uploads/mbed_official/hello.txt from developer.mbed.org:443
    ```

it probably means you need to update the contents of the `SSL_CA_PEM` constant (this can happen if you modify `HTTPS_SERVER_NAME`, or when `mbed.org` switches to a new CA when updating its certificate). Alternatively, this could mean someone is performing a man-in-the-middle attack on your connection. You can ignore this error and proceed with the connection anyway by changing the definition of `UNSAFE` near the top of the file from 0 to 1. **Warning:** this removes all security against an active attacker, use at your own risk, for debugging only!
