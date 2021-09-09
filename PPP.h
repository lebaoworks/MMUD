/**
 * Author:    Le Thieu Bao (https://github.com/lebaoworks)
 * Created:   07.09.2021
 * 
 * Based on RFC 1661, RFC 1994, RFC 1334
 **/

#pragma once
#include <stdint.h>

#define PACKET_MAX_LENGTH 0xFFFF
#define PACKET_MAX_DATA_LENGTH 0xFFFB // Exclude header


// LCP PACKET FORMAT
//     0                   1                   2                   3
//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |     Code      |  Identifier   |            Length             /        LCP Header
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |    Data...                                                             LCP Data
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//      (RFC 1661) - Section 5 LCP Packet Formats
//      LCP Header:
//          Code: Type of LCP Packet
//          Indentifier: A number used to match requests and replies
//          Length: Size of packet including the header
typedef struct _LCP_HEADER
{
    uint8_t code;
    uint8_t identifier;
    uint16_t length;
} LCP_HEADER;
typedef struct _LCP_PACKET
{
    LCP_HEADER header;
    uint8_t data[PACKET_MAX_DATA_LENGTH];
    
    // addition
    int data_len;
} LCP_PACKET;

#define LCP_CODE_CONFIG_REQUEST     1
#define LCP_CODE_CONFIG_ACK         2
#define LCP_CODE_CONFIG_NAK         3
#define LCP_CODE_CONFIG_REJECT      4
#define LCP_CODE_TERM_REQUEST       5
#define LCP_CODE_TERM_REJECT        6
#define LCP_CODE_REJECT             7
#define LCP_CODE_PROTO_REJECT       8
#define LCP_CODE_ECHO_REQUEST       9
#define LCP_CODE_ECHO_REPLY         10
#define LCP_CODE_DISCARD            11

// LCP CONFIGURATION REQUEST DATA FORMAT
// LCP CONFIGURATION ACK DATA FORMAT
// LCP CONFIGURATION NAK DATA FORMAT
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |     Option 1 ... /   Option 2 ... /   ....                         LCP Data
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+        
#define LCP_CONFIG_MAX_OPTIONS      8000
typedef struct _LCP_CONFIG_DATA
{
    int number_of_options;
    struct _OPTION
    {
        uint8_t type;
        void* addr;
    } options[LCP_CONFIG_MAX_OPTIONS];
} LCP_CONFIG_DATA;

// LCP CONFIGURATION REQUEST - AUTHENTICATION OPTION FORMAT
//     0                   1                   2                   3
//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |     Type      |    Length     |    Authentication-Protocol    |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+        LCP Data
//     |    Data ...
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//      (RFC 1661) - Section 6.2 Authentication-Protocol
//      LCP Data:
//          Type: Type of LCP Packet
//          Length: A number used to match requests and replies
//          Authentication-Protocol: indicates the authentication protocol desired
typedef struct _LCP_OPTION_AUTH_CHAP
{
    uint8_t type;
    uint8_t length;
    uint16_t auth_proto;
    uint8_t algorithm;
} LCP_OPTION_AUTH_CHAP;

typedef struct _LCP_OPTION_AUTH_PAP
{
    uint8_t type;
    uint8_t length;
    uint16_t auth_proto;
} LCP_OPTION_AUTH_PAP;

#define LCP_TYPE_RESERVE                    0
#define LCP_TYPE_MAXIMUM_RECEIVE            1
#define LCP_TYPE_AUTHENTICATION             3
#define LCP_TYPE_QUALITY                    4
#define LCP_TYPE_MAGIC                      5
#define LCP_TYPE_PROTO_COMPRESS             7
#define LCP_TYPE_ADDRESS_CONTROL_COMPRESS   8

#define LCP_AUTH_PROTO_PAP  0xC023
#define LCP_AUTH_PROTO_CHAP 0xC223
#define LCP_AUTH_CHAP_ALGORITHM_MD5 5


//----------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------//


// PAP PACKET FORMAT
//     0                   1                   2                   3
//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |     Code      |  Identifier   |            Length             |        PAP Header
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |    Data...                                                             PAP Data
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//      (RFC 1334) - Section 2.2 Packet Format
//      PAP Header:
//          Code: Type of packet
//          Indentifier: A number used to match requests and replies
//          Length: Size of packet including the header
typedef struct _PAP_HEADER
{
    uint8_t code;
    uint8_t identifier;
    uint16_t length;
} PAP_HEADER;
typedef struct _PAP_PACKET
{
    PAP_HEADER header;
    uint8_t data[PACKET_MAX_DATA_LENGTH];
    
    // addition
    int data_len;
} PAP_PACKET;

#define PAP_CODE_AUTH_REQUEST   1
#define PAP_CODE_ACK            2
#define PAP_CODE_NAK            3

// PAP AUTHENTICATION REQUEST DATA FORMAT
//     0                   1                   2                   3
//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     | Peer-ID Length|  Peer-Id ...
//     +-+-+-+-+-+-+-+-+-+-+-+-+                                                PAP Data
//     | Passwd-Length |  Password  ...
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//      (RFC 1334) - Section 2.2.1 Authenticate-Request
//      PAP Data:
//          Peer-ID Length: indicates the length of the Peer-ID field
//          Peer-ID: zero or more octets and indicates the name of the peer to be authenticated
//          Passwd-Length: indicates the length of the Password field
//          Password: zero or more octets and indicates the password to be used for authentication
typedef struct _PAP_REQUEST_DATA
{
    uint8_t peer_id_length;
    uint8_t* peer_id;
    uint16_t password_length;
    uint8_t* password;
} PAP_REQUEST_DATA;

// PAP RESPONSE DATA
//     0                   1                   2                   3
//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |  Msg-Length   |  Message  ...                                          PAP Data
//     +-+-+-+-+-+-+-+-+-+-+-+-+-
//
//      (RFC 1334) - Section 2.2.2  Authenticate-Ack and Authenticate-Nak
//      PAP Data:
//          Msg-Length: indicates the length of the Message field
//          Message: zero or more octets, and its contents are implementation dependent.
//              It is intended to be human readable, and MUST NOT affect operation of the protocol
typedef struct _PAP_RESPONSE_DATA
{
    int message_length;
    uint8_t* message;
} PAP_RESPONSE_DATA;



//----------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------//
//----------------------------------------------------------------------------------------------------------------//



// CHAP PACKET FORMAT
//     0                   1                   2                   3
//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |     Code      |  Identifier   |            Length             |        CHAP Header
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |    Data...                                                             CHAP Data
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//      (RFC 1994) - Section 4  Packet Format
//      CHAP Header:
//          Code: Type of packet
//          Indentifier: A number used to match requests and replies
//          Length: Size of packet including the header
typedef struct _CHAP_HEADER
{
    uint8_t code;
    uint8_t identifier;
    uint16_t length;
} CHAP_HEADER;
typedef struct _CHAP_PACKET
{
    CHAP_HEADER header;
    uint8_t data[PACKET_MAX_DATA_LENGTH];
    
    // addition
    int data_len;
} CHAP_PACKET;

#define CHAP_CODE_CHALLENGE     1
#define CHAP_CODE_RESPONSE      2
#define CHAP_CODE_SUCCESS       3
#define CHAP_CODE_FAILURE       4

// CHAP CHALLENGE/RESPONSE DATA FORMAT
//     0                   1                   2                   3
//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |  Value-Size   |  Value ...
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+        CHAP Data
//     |  Name ...
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//      (RFC 1994) - Section 4.1 Challenge and Response
//      CHAP Data:
//          Value-Size: size of value, equal or more than 1
//          Value: challenge_value for request / md5(concat(Identifier, secret, challenge_value)) for response
//          Name: identification of the system transmitting the packet. The size is determined from the Length field
    
typedef struct _CHAP_REQUEST_DATA
{
    uint8_t value_size;
    uint8_t* value;
    uint16_t name_size;
    uint8_t* name;
} CHAP_REQUEST_DATA, CHAP_RESPONSE_DATA;

// CHAP SUCCESS/FAILURE DATA FORMAT
//     0                   1                   2                   3
//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |  Message  ...                                                           CHAP Data
//    +-+-+-+-+-+-+-+-+-+-+-+-+-
//
//      (RFC 1994) - Section 4.2. Success and Failure
//      CHAP Data:
//          Message: zero or more octets, and its contents are implementation dependent.
//              It is intended to be human readable, and MUST NOT affect operation of the protocol.
typedef struct _CHAP_SUCCESS_DATA
{
    uint8_t* message;
    int message_size;
} CHAP_SUCCESS_DATA, CHAP_FAILURE_DATA;




#include "library/net.h"

int lcp_recv_packet(int fd, LCP_PACKET* packet)
{
    if (net_recvn(fd, (char*) packet, sizeof(LCP_HEADER)) != sizeof(LCP_HEADER))
        return -1;
    if (net_recvn(fd, (char*) packet->data, packet->header.length - sizeof(LCP_HEADER)) != packet->header.length - sizeof(LCP_HEADER))
        return -1;
    packet->data_len = packet->header.length - sizeof(LCP_HEADER);
    return 0;
}
int lcp_parse_packet(LCP_PACKET* packet, uint8_t type, void* packet_data)
{
    switch (type)
    {
        case (LCP_CODE_CONFIG_REQUEST):
        case (LCP_CODE_CONFIG_ACK):
        case (LCP_CODE_CONFIG_NAK):
        {
            LCP_CONFIG_DATA* lcp_config_data = (LCP_CONFIG_DATA*) packet_data;
            lcp_config_data->number_of_options = 0;
            int i=0;
            for (; i<packet->data_len; i++)
            {
                if (i<packet->data_len-1) // have at least 1 byte next
                {
                    lcp_config_data->options[lcp_config_data->number_of_options].type = packet->data[i];
                    lcp_config_data->options[lcp_config_data->number_of_options].addr = packet->data + i;
                    i += packet->data[i+1];
                }
            }
            if (i!=packet->data_len)
                return -1;
            return 0;
        }
        default:
            return -1;
    }
}

int pap_recv_packet(int fd, PAP_PACKET* packet)
{
    if (net_recvn(fd, (char*) packet, sizeof(PAP_HEADER)) != sizeof(PAP_HEADER))
        return -1;        
    if (net_recvn(fd, (char*) packet->data, packet->header.length - sizeof(PAP_HEADER)) != packet->header.length - sizeof(PAP_HEADER))
        return -1;
    packet->data_len = packet->header.length - sizeof(PAP_HEADER);
    return 0;
}
int pap_parse_packet(PAP_PACKET* packet, uint8_t type, void* packet_data)
{
    switch (type)
    {
        case (PAP_CODE_AUTH_REQUEST):
        {
            PAP_REQUEST_DATA* pap_request_data = (PAP_REQUEST_DATA*) packet_data;
            pap_request_data->peer_id_length = packet->data[0];
            pap_request_data->peer_id = packet->data + 1;
            pap_request_data->password_length = packet->data[1 + packet->data[0]];
            pap_request_data->password = packet->data + 1 + packet->data[0] + 1;
            return 0;
        }
        case (PAP_CODE_ACK):
        case (PAP_CODE_NAK):
        {
            PAP_RESPONSE_DATA* pap_response_data = (PAP_RESPONSE_DATA*) packet_data;
            pap_response_data->message_length = packet->data[0];
            pap_response_data->message = packet->data + 1;
        }
        default:
            return -1;
    }
}

int chap_recv_packet(int fd, CHAP_PACKET* packet)
{
    if (net_recvn(fd, (char*) packet, sizeof(CHAP_HEADER)) != sizeof(CHAP_HEADER))
        return -1;        
    if (net_recvn(fd, (char*) packet->data, packet->header.length - sizeof(CHAP_HEADER)) != packet->header.length - sizeof(CHAP_HEADER))
        return -1;
    packet->data_len = packet->header.length - sizeof(CHAP_HEADER);
    return 0;
}
int chap_parse_packet(CHAP_PACKET* packet, uint8_t type, void* packet_data)
{
    switch (type)
    {
        case (CHAP_CODE_CHALLENGE):
        case (CHAP_CODE_RESPONSE):
        {
            CHAP_REQUEST_DATA* chap_request_data = (CHAP_REQUEST_DATA*) packet_data;
            chap_request_data->value_size = packet->data[0];
            chap_request_data->value = packet->data + 1;
            chap_request_data->name_size = packet->header.length - sizeof(CHAP_HEADER);
            chap_request_data->name = chap_request_data->value + chap_request_data->value_size;
            return 0;
        }
        case (CHAP_CODE_SUCCESS):
        case (CHAP_CODE_FAILURE):
        {
            CHAP_SUCCESS_DATA* chap_response_data = (CHAP_SUCCESS_DATA*) packet_data;
            chap_response_data->message_size = packet->header.length - sizeof(CHAP_HEADER);
            chap_response_data->message = packet->data;
            return 0;
        }
        default:
            return -1;
    }
}