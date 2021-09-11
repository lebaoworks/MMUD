/**
 * Author:    Le Thieu Bao (https://github.com/lebaoworks)
 * Created:   07.09.2021
 * 
 * Demonstration of authorization phase in PPP-CHAP protocol
 *      Documentation: https://www.ietf.org/rfc/rfc1994.txt
 * 
 * Basic flow:
 *                      link establishment
 *              Peer ---------------------> Authenticator ---.
 *                                                           | Generate random as challenge ingeredient
 *                     challenge ingeredient                 v
 *          .-- Peer <--------------------- Authenticator <--'
 *          |
 *          | Calculate challenge answer from secret and challenge ingredient
 *          |
 *          |           challenge answer
 *          '-> Peer ---------------------> Authenticator ---.
 *                                                           | Calculate challenge answer from secret saved
 *                                                           |      and compare with the one from Peer
 *                             FAIL                        F v
 *        X <-- Peer <--------------------- Authenticator <--'
 *                                                           | T
 *                            SUCCESS                        v   
 *              Peer <--------------------- Authenticator <--'
 * 
 * Note:
 *      This is demostration about a scenario which CHAP authenticate smoothly.
 *      PPP Headers are not included.
 **/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h> 
#include <sys/socket.h>
#include <arpa/inet.h> 

#include "library/net.h"
#include "library/random.h"
#include "PPP.h"
#include "mbedtls/md5.h"

bool halt=false;
char secret[] = "Le Thieu Bao";

void peer_handler(int auth_fd)
{
    char buffer[PACKET_MAX_LENGTH];

    // Before Authentication phase
    // In Link Establishment phase, peer (or authenticator) must send Configuration Request through
    //      PPP Link Control Protocol, otherwise Authentication phase will be ignored
    //
    //      (RFC 1661) - Section 5.1 Configuration-Request
    //      LCP Header:
    //          Code: 1 (Configure-Request)
    //      
    //      (RFC 1661) - Section 6 LCP Configuration Options
    //      (RFC 1994) - Section 3 Configuration Option Format
    //      LCP Data:
    //          1 - Authentication-Protocol:
    //              Type: 3 (Authentication-Protocol)
    //              Length: 5 (Size of option)
    //              Authentication-Protocol: 0xC223 (Challenge-Handshake Authentication Protocol)
    //              Algorithm: 5 (CHAP with MD5)  
    LCP_PACKET* lcp_packet = (LCP_PACKET*) buffer;
    LCP_OPTION_AUTH_CHAP* lcp_option_auth = (LCP_OPTION_AUTH_CHAP*) lcp_packet->data;
    // write option data
    lcp_option_auth->type = LCP_TYPE_AUTHENTICATION;
    lcp_option_auth->length = sizeof(LCP_OPTION_AUTH_CHAP);
    lcp_option_auth->auth_proto = LCP_AUTH_PROTO_CHAP;
    lcp_option_auth->algorithm = LCP_AUTH_CHAP_ALGORITHM_MD5;
    // write header
    lcp_packet->header.code = LCP_CODE_CONFIG_REQUEST;
    lcp_packet->header.identifier = 1;
    lcp_packet->header.length = sizeof(LCP_HEADER) + sizeof(LCP_OPTION_AUTH_CHAP);
    // send packet
    net_sendn(auth_fd, (char*) lcp_packet, lcp_packet->header.length);
    printf("[*] Sent CONFIG_REQUEST\n");

    //
    // Receive Configuration Response
    //
    if (lcp_recv_packet(auth_fd, lcp_packet) ||
        lcp_packet->header.code != LCP_CODE_CONFIG_ACK)
    {
        printf("[!] PACKET -> not expected!\n");
        return;
    }
    printf("[+] CONFIG_REQUEST -> success!\n");   

    //
    // Receive Challenge Request
    //
    CHAP_PACKET* chap_packet = (CHAP_PACKET*) buffer;
    if (chap_recv_packet(auth_fd, chap_packet) ||
        chap_packet->header.code != CHAP_CODE_CHALLENGE)
    {
        printf("[!] PACKET -> not expected\n");
        return;
    }
    uint8_t value_size = chap_packet->data[0];
    uint8_t* value = chap_packet->data + 1;
    uint8_t* name = chap_packet->data + 1 + value_size;
    // Show value
    printf("[*] got CHALLENGE_REQUEST:\n\tID: %u\n\tValue-Size: %u\n\tValue: 0x", chap_packet->header.identifier, value_size);
    for (uint8_t* i=value; i<name; i++)
        printf("%02X", *i);
    printf("\n\tName: 0x");
    for (uint8_t* i=name; i<(uint8_t*) chap_packet + chap_packet->header.length; i++)
        printf("%02X", *i);
    printf("\n");

    //
    // Calculate response = hash(concat(Identifier, secret, Value))
    //
    uint8_t* concat = malloc(1 + strlen(secret) + value_size);
    concat[0] = chap_packet->header.identifier;
    memcpy(concat+1, secret, strlen(secret));
    memcpy(concat+1+strlen(secret), value, value_size);
    // hash MD5, store to value
    if (mbedtls_md5(concat, 1 + strlen(secret) + value_size, value))
    {
        printf("[!] HASH -> fail\n");
        free(concat);
        return;
    }
    free(concat);
    printf("[*] Hash: ");
    for (int i=0; i<16; i++)
        printf("%02X ", value[i]);
    printf("\n");

    //
    // send CHAP RESPONSE packet
    //
    // CHAP RESPONSE PACKET FORMAT
    //      (RFC 1994) - Section 4.1 Challenge and Response
    //      CHAP Header:
    //          Code: 2 (Challenge)
    //      CHAP Data:
    //          Value-Size: 16
    //          Value: md5(concat(Identifier, secret, challenge_value))
    //          Name: identification of the system transmitting the packet. The size is determined from the Length field

    // write value size
    chap_packet->data[0] = 16; // MD5 always returns 128-bit hash
    // write name
    name = "bao_peer";
    memcpy(chap_packet->data+1+16, name, strlen(name));
    // write header
    chap_packet->header.code = CHAP_CODE_RESPONSE;
    chap_packet->header.length = sizeof(CHAP_HEADER) + 1 + 16 + strlen(name);
    // send packet
    net_sendn(auth_fd, (char*) chap_packet, chap_packet->header.length);
    printf("[*] send RESPONSE packet!\n");

    //
    //  receive response
    //
    if (chap_recv_packet(auth_fd, chap_packet))
    {
        printf("[!] PACKET -> not expected\n");
        return;
    }
    if (chap_packet->header.code == CHAP_CODE_SUCCESS)
    {
        printf("[+] Authenticated -> success\n");
        printf("\tMessage: ");
        for (int i=0; i<chap_packet->header.length - sizeof(CHAP_HEADER); i++)
            printf("%c", chap_packet->data[i]);
        printf("\n");
    }
    else
        if (chap_packet->header.code == CHAP_CODE_FAILURE)
        {
            printf("[-] Authenticated -> fail\n");
            printf("[+] Authenticated -> success\n");
            printf("\tMessage: ");
            for (int i=0; i<chap_packet->header.length - sizeof(CHAP_HEADER); i++)
                printf("%c", chap_packet->data[i]);
            printf("\n");
        }
    else
        printf("[!] PACKET -> not expected\n");
}

void auth_handler(int peer_fd, struct sockaddr_in* peer_addr)
{
    printf("\n[*] got connect from %s\n", inet_ntoa(peer_addr->sin_addr));
    char buffer[PACKET_MAX_LENGTH];

    //
    // Receive Configuration Request
    //
    LCP_PACKET* lcp_packet = (LCP_PACKET*) buffer;
    if (lcp_recv_packet(peer_fd, lcp_packet) ||
        lcp_packet->header.code != LCP_CODE_CONFIG_REQUEST)
    {
        printf("[!] PACKET -> not expected\n");
        return;
    }
    // peer send only 1 option (authentication option)
    LCP_OPTION_AUTH_CHAP* lcp_option_auth = (LCP_OPTION_AUTH_CHAP*) lcp_packet->data;
    printf("[*] got CONFIG_REQUEST:\n\tType: %u\n\tLength: %u\n\tProtocol: 0x%X\n\tAlgorithm: %u\n",
        lcp_option_auth->type,
        lcp_option_auth->length,
        lcp_option_auth->auth_proto,
        lcp_option_auth->algorithm
    );

    //
    // Check and response configuration
    //
    if (lcp_option_auth->type != LCP_TYPE_AUTHENTICATION ||
        lcp_option_auth->auth_proto != LCP_AUTH_PROTO_CHAP ||
        lcp_option_auth->algorithm != LCP_AUTH_CHAP_ALGORITHM_MD5)
    // Send Configure Nak
    //      (RFC 1661) - Section 5.3 Configure-Nak
    //      LCP Header:
    //          Code: 3 (Configure-Nak)
    //      LCP Data:
    //            LCP Options that are not acceptable
    {
        printf("[-] not acceptable -> send NAK \n");
        lcp_packet->header.code = LCP_CODE_CONFIG_NAK;
        // Send the same because there is only 1 option from peer.
        net_sendn(peer_fd, (char*) lcp_packet, lcp_packet->header.length);
        return;
    }
    else
    // Send Configure Nak
    //      (RFC 1661) - Section 5.2 Configure-Ack
    //      LCP Header:
    //          Code: 2 (Configure-Ack)
    //      LCP Options:
    //          Configuration Options MUST NOT be reordered or modified in any way.
    {
        printf("[+] acceptable -> send ACK\n");
        lcp_packet->header.code = LCP_CODE_CONFIG_ACK;
        net_sendn(peer_fd, (char*) lcp_packet, lcp_packet->header.length);
    }

    //
    // Start Authentication phase through PPP CHAP Protocol
    //
    // CHAP CHALLENGE PACKET FORMAT
    //      (RFC 1994) - Section 4.1 Challenge and Response
    //      CHAP Header:
    //          Code: 1 (Challenge)
    //      CHAP Data:
    //          Value-Size: size of value, equal or more than 1
    //          Value: challenge
    //          Name: identification of the system transmitting the packet. The size is determined from the Length field

    CHAP_PACKET* chap_packet = (CHAP_PACKET*) buffer;
    // generate random value
    uint8_t value_size = rand_int(1, 255);
    chap_packet->data[0] = value_size;
    rand_str(chap_packet->data+1, value_size);
    // write name
    char name[] = "bao_auth";
    memcpy(chap_packet->data + 1 + value_size, name, strlen(name));
    // write header
    chap_packet->header.code = CHAP_CODE_CHALLENGE;
    chap_packet->header.identifier = rand_int(0, 255);
    chap_packet->header.length = sizeof(CHAP_HEADER) + 1 + value_size + strlen(name);
    // send packet
    net_sendn(peer_fd, (char*) chap_packet, chap_packet->header.length);
    // show value
    printf("[*] sent CHALLENGE_REQUEST:\n\tID: 0x%02X\n\tValue-Size: %u\n\tValue: 0x", chap_packet->header.identifier, value_size);
    for (int i=0; i<value_size; i++)
        printf("%02X", chap_packet->data[1+i]);
    printf("\n\tName: 0x");
    for (int i=0; i<strlen(name); i++)
        printf("%02X", name[i]);
    printf("\n");
    
    //
    // receive response
    //
    char buffer2[PACKET_MAX_LENGTH];
    CHAP_PACKET* chap_packet2 = (CHAP_PACKET*) buffer2;
    if (chap_recv_packet(peer_fd, chap_packet2) ||
        chap_packet2->header.code != CHAP_CODE_RESPONSE)
    {
        printf("[!] PACKET -> not expected!\n");
        return;
    }
    CHAP_RESPONSE_DATA chap_response_data;
    chap_parse_packet(chap_packet2, CHAP_CODE_RESPONSE, &chap_response_data);
    if (chap_response_data.value_size != 16)
    {
        printf("[!] CHAP_DATA -> malformatted!\n");
        return;
    }
    printf("[+] got RESPONSE:");
    for (int i=0; i<chap_response_data.value_size; i++)
        printf("%02X ", chap_response_data.value[i]);
    printf("\n");

    //
    // recalculate answer
    //
    CHAP_REQUEST_DATA chap_request_data;
    chap_parse_packet(chap_packet, CHAP_CODE_RESPONSE, &chap_request_data);
    uint8_t recalculate[16];
    // concat
    uint8_t* concat = malloc(1 + strlen(secret) + value_size);
    concat[0] = chap_packet->header.identifier;
    memcpy(concat+1, secret, strlen(secret));
    memcpy(concat+1+strlen(secret), chap_request_data.value, chap_request_data.value_size);
    // hash MD5, store to value
    if (mbedtls_md5(concat, 1 + strlen(secret) + chap_request_data.value_size, recalculate))
    {
        printf("[!] HASH -> fail\n");
        free(concat);
        return;
    }
    free(concat);
    printf("[*] Recalculate: ");
    for (int i=0; i<16; i++)
        printf("%02X ", recalculate[i]);
    printf("\n");

    //
    // compare and response
    //
    if (strncmp(chap_response_data.value, recalculate, 16) == 0)
    // send CHAP SUCCESS packet
    //      (RFC 1994) - Section 4.2. Success and Failure
    //      CHAP Header:
    //          Code: 3 (Success)
    //      CHAP Data:
    //          Message: zero or more octets, and its contents are implementation dependent.
    //              It is intended to be human readable, and MUST NOT affect operation of the protocol.
    {
        printf("[+] Response correct!\n");
        memcpy(chap_packet->data, "OK", 2);
        chap_packet->header.code = CHAP_CODE_SUCCESS;
        chap_packet->header.length = sizeof(CHAP_HEADER) + 2;
        net_sendn(peer_fd, (char*) chap_packet, chap_packet->header.length);
    }
    else
    // send CHAP FAILURE packet
    //      (RFC 1994) - Section 4.2. Success and Failure
    //      CHAP Header:
    //          Code: 4 (Success)
    //      CHAP Data:
    //          Message: zero or more octets, and its contents are implementation dependent.
    //              It is intended to be human readable, and MUST NOT affect operation of the protocol.
    {
        printf("[-] Response incorrect!\n");
        memcpy(chap_packet->data, "FAIL", 4);
        chap_packet->header.code = CHAP_CODE_FAILURE;
        chap_packet->header.length = sizeof(CHAP_HEADER) + 4;
        net_sendn(peer_fd, (char*) chap_packet, chap_packet->header.length);
    }

}
int main(int argc, char* argv[])
{
    if (argc != 2)
        goto error;

    if (strcmp(argv[1], "peer") == 0)
    {
        int fd = net_tcp_connect(DEFAULT_ADDR, DEFAULT_PORT);
        if (fd != -1)
            peer_handler(fd);
        else
            printf("Can not connect to authenticator!\n");
        close(fd);
    }
    else if (strcmp(argv[1], "auth") == 0)
        net_tcp_server(DEFAULT_ADDR, DEFAULT_PORT, auth_handler, &halt);
    else
        goto error;
    return 0;

    error:
    printf("Usage: %s peer/auth\n\tRun an instance with \"auth\" and then run \"peer\" to see result.", argv[0]);
    return 1;
}



