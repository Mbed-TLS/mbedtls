Reassembly of incoming fragmented TLS handshake messages
========================================================

This document describes the design of the implementation of reassembly of incoming TLS handshake messages as enabled by the configuration option `MBEDTLS_SSL_TLS_HANDSHAKE_REASSEMBLY` and the SSL API `mbedtls_ssl_conf_hs_reassembly_set_max_message_size()`.

## Introduction

The fragmentation of the outgoing TLS handshake messages is currently not supported in Mbed TLS. Fragmentation and reassemly of DTLS handshake messages is supported in Mbed TLS, but not documented here.

### Goals

1. Full backwards compatibility with the "development" branch of Mbed TLS, unless the user explicitly enables fragmentation support in `config.h` via `MBEDTLS_SSL_TLS_HANDSHAKE_REASSEMBLY` option, and in application code via `mbedtls_ssl_conf_hs_reassembly_set_max_message_size()` API.
2. Keeping the the conceptual changes to the Mbed TLS codebase to the necessary minimum.
3. Robustness and simplicity.

### Non-goals

The below goals are out of scope of this PR:

1. Fragmentation of outgoing TLS handshake messages.
2. Reassembling the Change Cipher Spec and the Alert messages.
3. Unification of the mechanisms used for reassembly and fragmentation of TLS and DTLS handshake messages.

# Detailed description of the problem

During the establishment of a TLS connection, the two participating endpoints exchange TLS handshake messages to agree upon the critical security parameters (see [RFC 5246 TLS 1.2](https://tools.ietf.org/html/rfc5246#section-7) for more details).

The handshake messages are exchanged via TLS records. The TLS protocol places no restrictions on how the TLS hanshake messages should reside within the TLS records, and the TLS handshake messages may be broken into several fragments.

For example, a typical TLS handshake may start with the following interaction:

```
Client                                   Server

ClientHello      -------->
                                    ServerHello
                                    Certificate
                              ServerKeyExchange
                 <--------      ServerHelloDone
```


In the above scenario, the server may opt to send the sequence of 4 handshake messages as a single consecutive data block. If the block can not fit a single TLS record, the server endpoint may choose to deliver the block in two TLS records, in which case one of the messages can become fragmented, like the `Certificate` message in the following example:

```
+------------------------+------------------------------------+
| TLS record 0           | TLS record 1                       |
| +-------------+--------+-----+-------------------+---------+|
| |Server Hello | Certificate  |Server Key Exchange|  Done   ||
| +-------------+--------+-----+-------------------+---------+|
+------------------------+------------------------------------+
```

In such case, the client endpoint will have to reassemble the fragmented `Certificate` message.

Unlike the DTLS protocol, which relies on special sub-headers (rfc6347) to guarantee proper delivery of fragmented messages, the TLS protocol relies on the underlying TCP transport. Because of that, no special measures are taken to indicate that a TLS record does not contain a full message. It is up to the receiving endpoint to keep the necessary state. In particular, the receiving endpoint needs to know the length of the current message, and how much of it was already received.

The following examples illustrate some common fragmentation patterns:

1. The body of the handshake message is split in two fragments. The header is not fragmented:

```
+------------------------+------------------------+
| TLS record 0           | TLS record 1           |
| +----------------------+----------------------+ |
| | Hdr | Body frag #0   | Body frag #1         | |
| +----------------------+----------------------+ |
+------------------------+------------------------+
```

2. The header of a handshake message is fragmented:

```
+------------------------+------------------------+
| TLS record 0           | TLS record 1           |
|          +-------------+----------------------+ |
|   ...    | Hdr frag #0 | Hdr frag #1 | Body   | | 
|          +-------------+----------------------+ |
+------------------------+------------------------+
```

3. The header of a handshake message is separated from the body:

```
+-----------------+------------------------+
| TLS record 0    | TLS record 1           |
|          +------+----------------------+ |
|   ...    | Hdr  |  Body                | | 
|          +------+----------------------+ |
+-----------------+------------------------+
```

# High-level overview of the implementation

The message-handling code relies on "MPS reader" to accumulate message fragments:

```
+------------------------+------------------------+
| TLS record 0           | TLS record 1           |
| +----------------------+----------------------+ |
| | Hdr | Body frag #0   | Body frag #1         | |
| +----------------------+----------------------+ |
+------------------------+------------------------+
                |          
                |             +------------------+
                v             | Reassembly State |
          +---------+   <---> +------------------+
          |  MPS    |         
          |  Reader |
          +---------+   <---> +--------------------+
                |             | Reassembly Arena   |
                |             +--------------------+
                v
            +-----+------------------+
            | Hdr | Reassembled body |
            +------------------------+
```


### Consuming TLS records

The contents of the incoming TLS records are unconditionally passed to the MPS reader. When the TLS handshake state machine needs a new handshake message, it attempts to retrieve it from the MPS reader, via the `ssl_read_record()` API.

## Reassembling handshake messages from fragments

To support the variety of ways in which the fragmented handshake messages can arrive, `ssl_read_record()` gets the handshake message data in two steps: first, the header; then the body.

If the handshake message is not fragmented, both steps succeed and `ssl_read_record()` returns 0 to indicate that a handshake message can be used. Otherwise, it returns an error code that indicates that more IO is required to get the message.

When this happens, the MPS reader will keep track on the failed attempt to read data, and will retain the portion of the message that was avaiable. When contents of the next TLS records are passed to the MPS reader, the reader will concatenate the new content to the retained data. 

Once the MPS reader has enough data, the call to `ssl_read_record()` will succeed.

## Accessing the handshake message

With the introduction of reassembly, the actual hanshake message can reside in several places. If the entire handshake message was fully contained in a single TLS record, and no actual reassembly was necessary, the handshake message will remain in the `ssl->in_msg` buffer. If the message had been fragmented, the reassembled message will be rebuilt in the memory arena that the MPS reader is using. Because of that, the TLS state machine uses dedicated helper functions to access the handshake message. See the "Handshake Message Access API" section below for details.

## State / Resource management

The MPS reader uses a dedicated memory arena for accumulating the message fragments. This arena, plus the necessary state are contained in a so-called "reassembly control block" (aka `rcb`) to keep track of the necessary state.

Once the reassembled handshake message had been fully processed, that memory needs to be recovered, so that it can be used for the future messages. This is done at the beginning of each `ssl_read_record()` invocation.

See the "Reassembly State Management" and "Reassembly Resource Management" sections below for a detailed description of the process and of the reassembly control blocks.


# API Extensions

## Compile-time options

```
/**
 * \def MBEDTLS_SSL_TLS_HANDSHAKE_REASSEMBLY
 *
 * Allows the client to reassemble fragmented TLS handshake messages.
 *
 * Requires: MBEDTLS_MPS_READER_C
 *
 */
#define MBEDTLS_SSL_TLS_HANDSHAKE_REASSEMBLY

/**
 * \def MBEDTLS_SSL_HANDSHAKE_REASSEMBLY_MAX_MESSAGE_SIZE
 *
 * Sets the maximal length for the reasembled TLS handshake message,
 * including the handshake message header.
 *
 * If not defined, the limit defaults to 16384
 *
 * This value of this option controls the amount of RAM that will be
 * dynamically allocated by the handshake reassembly module when
 * it receives a fragmented handshake message.
 *
 * Requires: MBEDTLS_SSL_TLS_HANDSHAKE_REASSEMBLY
 */
//#define MBEDTLS_SSL_HANDSHAKE_REASSEMBLY_MAX_MESSAGE_SIZE 16384
```

## Configuration API

A new error constant `MBEDTLS_ERR_SSL_HS_REASSEMBLY_MAX_MESSAGE_SIZE_EXCEEDED`
indicates that the handshake message can not be processed because of the maximal message size
limitation.

```
/**
 * \brief          Sets maximal length of a reassembled handshake message.
 *
 * The `max_size` paramter controls the amount of RAM that will be dynamically
 * allocated by the handshake reassembly module when it receieves a fragmented
 * handshake message.
 *
 * If the `max_size` paramter is set to 0, handshake reassembly is disabled.
 * This is the default setting.
 *
 *
 * \param conf     SSL configuration
 * \param max_size Maximal length of the reassembled messsage. 0 disables reassembly.
 *
 * \return         0 on success
 * \return         MBEDTLS_ERR_SSL_HS_REASSEMBLY_MAX_MESSAGE_SIZE_EXCEEDED
 *                 if the requested max_size exceeds the compile-time option.
 */
int mbedtls_ssl_conf_hs_reassembly_set_max_message_size( mbedtls_ssl_config *conf, size_t max_message_size );
```

## Handshake Message Access API

Since the contents of the handshake message can reside either in `ssl->in_msg` buffer, or in the accumulation arena, the code that uses the handshake messages (such as the handshake state machine) should avoid accessing the hadnshake message directly.

Instead, the following internal helper functions are provided:

```
/* Returns the type of the handshake message, or -1 if not available */
char mbedtls_ssl_hs_type( const mbedtls_ssl_context *ssl );
```

```
/* Returns the length of the handshake message (including the header), or -1 if not available */
size_t mbedtls_ssl_hs_len( const mbedtls_ssl_context *ssl );
```

```
/* Returns the length of the body of the handshake message, or -1 if not available */
size_t mbedtls_ssl_hs_body_len( const mbedtls_ssl_context *ssl );
```

```
/* Returns a pointer to the header of the handshake message */
static inline unsigned char *mbedtls_ssl_hs_hdr_ptr( const mbedtls_ssl_context *ssl )
```

```
/* Returns the pointer to the body of the handshake message, or NULL if not availble */
unsigned char *mbedtls_ssl_hs_body_ptr( const mbedtls_ssl_context *ssl );
```

## MPS reader API

Conceptually, the `mbedtls_reader` is a FIFO buffer, that offers the following API:

- `mbedtls_reader_feed()`    - appends data to the "tail" of the FIFO.
- `mbedtls_reader_get()`     - provides access to the "head" of the FIFO.
- `mbedtls_reader_commit()`  - informs the "FIFO" that the data that have been previously
                               requested via `mbedtls_reader_get()` have been processed.
- `mbedtls_reader_reclaim()` - cleans up the space that's occupied by the already committed
                               messages.

# Implementation Details

## Detailed description of `ssl_read_record()`

The TLS state machine uses `mbedtls_ssl_read_record()` function to read a new handshake message. The name of the function may be misleading - it is "reading" the contents of a TLS _record_ in order to prepare the TLS handshake _message_.

The function is reentrant, and it keeps the reassembly-related state in a "Reassembly Control Block" structure (aka `hs_rcb`), which is described in the following section.

### Invocation and return values
If the user-provided I/O callbacks `ssl->f_recv` and `ssl->f_recv_timeout` are non-blocking, the function `mbedtls_ssl_read_record()` may run out of data. In such case it will return value `MBEDTLS_ERR_SSL_WANT_READ`, which indicates that the function has to be invoked again, after I/O activity. 

Regardless of the behavior of the I/O callbacks, return value 0 indicates that a handshake message have been successfuly prepared, and that the TLS state machine can access it via the helper functions `mbedtls_ssl_hs_{type,length,get_hdr_ptr,get_body_ptr}()` (see "Access API" for details).

Other return values indicate a fatal error.

### Outline of the function

Every invocation of `mbedtls_ssl_read_record()` starts with invocation of `ssl_consume_current_message()` to release the resources used by the last handshake message, if that message has been fully processed. 

At the next step, `mbedtls_ssl_read_record()` uses `ssl_record_is_in_progress()` to check whether the current TLS record contains. The latter function uses differnt mechanisms depending on whether the reassembly is being used. If reassembly is not in use, `ssl_record_is_in_progress()` relies on the `ssl->in_msglen` field. Otherwise, it checks whether the MPS reader has remaining bytes which have not been consumed. Note: this functionality probably belongs to the MPS API.

If more data is needed, `mbedtls_ssl_read_record()` uses `ssl_get_next_record()` to fetch and decrypt a new TLS record. If successful, `mbedtls_ssl_read_record()` uses `ssl_hs_accumulate_fragments()` to pass the contents of the newly read TLS record to the MPS reader.

At this point, the function is ready to attempt to extract a new handshake message. It uses `mbedtls_ssl_handle_message_type()` for this purpose, which in turn invokes `mbedtls_ssl_prepare_handshake_record()`.

The function `mbedtls_ssl_prepare_handshake_record()` checks whether it needs to read the header of the next handshake message from the MPS reader. This is determined by the `ssl->handsake->hs_rcb.state` field.

In case the header needs to be read, `mbedtls_ssl_prepare_handshake_record()` attempts to read the 4 bytes which constitute the handshake message header from the MPS reader, via `mbedtls_reader_get`. If the reader contains the header, `mbedtls_ssl_prepare_handshake_record()` retains the header bytes in the reassembly control block; otherwise `mbedtls_ssl_read_record()` loops back and tries to get another TLS record.

Once the header bytes are ready, `mbedtls_ssl_prepare_handshake_record()` attempts to read the body of the handshake message from the MPS reader. Likewise, if the MPS reader does not contain sufficient data for the handshake message, the `mbedtls_ssl_read_record()` function loops back and tries to get another TLS record.

Once the body bytes are ready, `mbedtls_ssl_read_record()` returns with value 0, which indicates that the TLS state machine can access the handshake message.


```
                       
                       |                                 
                       v                                 
           +-------------------------------------------+ 
           | consume_current_message()                 | 
           |                                           | 
           | Prepare for a new handshake message:      | 
           | 1. Commit and reclaim the MPS buffers.    | 
           | 2. If the state indicates that entire     | 
           |   message has been read, reset the state. | 
           +-------------------------------------------+ 
                       |                                 
                       |                                 
                       v                                 
            +-------------------------------------------+
            | ssl_record_is_in_progress()               |
            |                                           |
            | Check for unprocessed data from the       |
            | last TLS record.                          |
            +-------------------------------------------+
                       |                                 
                       |                                 
                       v                                 
                 +--------------------------------------------+     
                 | ssl_get_next_record()                      |     
                 |                                            |     
                 | Attempt to read a full TLS record.         |     
    +-fail------ | If more data needed, return to the caller, |<----------+
    |            | indicating that ssl_read_record needs      |           |
    |            | to be invoked again.                       |           |
    |            +--------------------------------------------+           |
    |                        |                                            |
    |                        |                                            |
    |                        |                                            |
    |                        v                                            |
    |             +-------------------------------------------+           |
    |             | ssl_hs_accumulate_fragments()             |           |
    |             |                                           |           |
    |             | Pass the contents of the TLS record to    |           |
    |             | the MPS reader.                           |           |
    |             +-------------------------------------------+           |
    |                        |                                            |
    |                        |                                            |
    |                        v                                            |
    |             +--------------------------------------------+          |
    |             | prepare_handshake_record()                 |   Not enough data
    |             |                                            |   in the MPS reader
    |             | Attempt to get the handshake message from  |          |
    |             | the MPS reader.                            |          |
    |             | Depending on the RCB state, read body only |          |
    |             | or header followed by the body.            |          |
    |             | If the MPS reader does not have the data,  |----------+
    |             | return to the caller, indicating that      |
    |             | ssl_read_record needs to be invoked again. |
    |             +--------------------------------------------+
    |                         |
Not enough data           Complete handshake message
caller must invoke        is available
again                         |
    v                         v
  /----------------------------\
  |   Return to the caller     |
  \----------------------------/
``` 
    

## Reassembly State Management 

To keep track of the reassembly process, `struct mbedtls_ssl_handshake_params` is extended with a "reassembly control block" structure:

```
struct mbedtls_ssl_hs_reassembly
{
    mbedtls_reader *reader;     /*!< MPS reader for consuming HS messages */
    size_t         acc_len;     /*!< Length of the accumulator arena */
    unsigned char  *acc;        /*!< Accumulator arena */
    unsigned char  *pmsg;       /*!< Ptr to the reassembled handshake message */
    unsigned char  hdr[4];      /*!< Copy of the handshake header */

    enum mbedtls_ssl_hs_reassembly_state
    {
       RCB_STATE_NONE,          /*!< No data available */
       RCB_STATE_HAS_HDR,       /*!< Has handshake header */
       RCB_STATE_HAS_FULL_MSG,  /*!< Has the entire message */
    } state;
} hs_rcb;
```

### The message pointer

When the MPS reader indicates that a message is available for consumption, it may reside in two locations:

1. In the `ssl->in_msg` buffer (possibly at some offset), if the message was not fragmented.
2. In the `acc` arena, (possibly at some offset), if the messag was fragmented and had to be reassembled with the `acc` arena.

In both cases, the `mbedtls_reader_get()` function will set the `hs_rcb.pmsg` pointer to the right location.

### The `hdr` buffer

The assumption that the header and the body of the reassembled message occupy the same contiguous buffer is not true when the reassembly is used. In particular, if the header and the body of the handshake message are separated, then the header of the handshake message will not be copied to the accumulator arena:


```
+-----------------+------------------------+
| TLS record 0    | TLS record 1           |
|          +------+----------------------+ |
|   ...    | Hdr  |  Body                | | 
|          +------+----------------------+ |
+-----------------+------------------------+
```

As explained above, when `mbedtls_ssl_prepare_handshake_record()` processes a message, it makes two calls to `mbedtls_reader_get()`: one to read the header, and one to read the body of the message. 

When the header and the body are separated, the first call to `mbedtls_reader_get()` will succeed, because the entire header is present in the `ssl->in_msg` buffer. Because of that, its output param will point to some offset in `ssl->in_msg`, and the MPS reader will not use the `hs_rcb.acc` arena.

The subsequent invocation of `mbedtls_reader_get()` will fail, since the first TLS record does not contain the body of the handshake message. Once the subsequent TLS record will have been read, the `ssl->in_msg` buffer will contain the new data.

To correctly support the case, the code always keeps a copy of the header in the `hs_rcb.hdr` buffer.


### `RCB_STATE` state machine

If the header of the handshake message has already been retrieved, the `mbedtls_ssl_prepare_handshake_record()` function should not attempt to read it again. To keep track of the state of the header, the code uses the `hs_rcb.state` field, which has the following state transition diagram.

```
    .-----------------.              
   (  RCB_STATE_NONE   )<----+       
    `-----------------'      |       
             |               |       
prepare_handshake_message    |       
        (header)             |       
             |               |       
             v               |       
  .---------------------.   consume  
 (   RCB_STATE_HAS_HDR   )  message  
  `---------------------'    |       
             |               |       
  prepare_handshake_message  |       
           (body)            |       
             |               |       
             v               |       
 .-----------------------.   |       
( RCB_STATE_HAS_FULL_MSG  )--+       
 `-----------------------'           
```

Note: currently, the state is using an `int`-sized field. There is an optimization opportunity: the first byte of the saved header does not use all 8 bits. 3 highest bits can be used to keep track of the state. At the moment, the code makes the trade-off towards a simpler implementation.

## Reassembly Resource Management

### Accumulator Arena

The accumulator arena is dynamically allocated together with the `ssl->handshake`, and is released once the handshake is over. This way, the memory can be reused.

Once allocated, the usage of the accumulator arena is governed by the MPS reader. At every invocation of `mbedtls_ssl_read_record()` the function `ssl_consume_current_message()` is invoked. When reassembly is used, the function invokes `mbedtls_reader_commit()`, to indicate that every successful read request won't be needed again, followed by `mbedtls_reader_reclaim()`, which will attempt to free up space in the accumulator arena for future messages.

## Configuration

The maximal message length is stored in the `struct mbedtls_ssl_config`:

```
struct mbedtls_ssl_config {
...
#if defined(MBEDTLS_SSL_TLS_HANDSHAKE_REASSEMBLY)
    /** Maximal supported message size. Value 0 indicates that the reassembly is disabled.*/
    size_t hs_reassembly_max_message_size;
#endif /* MBEDTLS_SSL_TLS_HANDSHAKE_REASSEMBLY */
...
};
```

# Example configuration:

```
/** Enable handshake reassembly. */
#define MBEDTLS_SSL_TLS_HANDSHAKE_REASSEMBLY

/** Hard limit for the maximal message size. */
#define MBEDTLS_SSL_HANDSHAKE_REASSEMBLY_MAX_MESSAGE_SIZE 16368
```
