#include <string.h>
#include <unistd.h>

#include <psa/crypto.h>

#include "common.h"
#include "util.h"

psa_status_t send_psa_message(psa_message_t *psa_message, size_t payload_len, int sockfd)
{
    socket_message_t socket_message = { 0 };
    size_t socket_message_len;
    /* The amount of bytes that must be transmitted is payload + the "header" of psa_message_t. */
    size_t bytes_left = PSA_MESSAGE_HEADER_LENGTH + payload_len;
    size_t chunk_size;
    uint8_t *ptr = (uint8_t *) psa_message;
    size_t written_bytes;

    /* Since it's very likely that psa_message_t will be quite large in size, we
     * split it into chunks and send them to the server. */
    while (bytes_left > 0) {
        chunk_size = (bytes_left > MAX_SOCKET_PAYLOAD_LENGTH) ?
                     MAX_SOCKET_PAYLOAD_LENGTH : bytes_left;
        bytes_left -= chunk_size;
        socket_message.is_last_message = (bytes_left == 0);
        socket_message.length = chunk_size;
        memset(socket_message.payload, 0, MAX_SOCKET_PAYLOAD_LENGTH);
        memcpy(socket_message.payload, ptr, chunk_size);
        ptr += chunk_size;
        socket_message_len = SOCKET_MESSAGE_HEADER_LENGTH + chunk_size;
        written_bytes = write(sockfd, &socket_message, socket_message_len);
        if (written_bytes < 0) {
            ERROR("Unable to write data to socket.");
            return PSA_ERROR_COMMUNICATION_FAILURE;
        }
    }

    return PSA_SUCCESS;
}
