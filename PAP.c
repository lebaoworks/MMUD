/**
 * Author:    Le Thieu Bao (https://github.com/lebaoworks)
 * Created:   07.09.2021
 * 
 * Demonstration of authorization phase in PPP-PAP protocol
 *      Documentation: https://www.ietf.org/rfc/rfc1334.txt
 * 
 * Basic flow:
 *                      link establishment
 *              Peer ---------------------> Authenticator
 *                                                            
 *                     peer_id, password             
 *              Peer ---------------------> Authenticator ---.
 *                                                           |  compare with data saved
 *                                                           |
 *                             FAIL                        F v
 *        X <-- Peer <--------------------- Authenticator <--'
 *                                                           | T
 *                            SUCCESS                        v   
 *              Peer <--------------------- Authenticator <--'
 * 
 * Note:
 *      This is demostration about a scenario which PAP authenticate smoothly.
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

bool halt=false;
char peer_id[] = "Le Thieu Bao";
char passwd[] = "Bao Le Thieu";

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
    //      (RFC 1334) - Section 3 Configuration Option Format
    //      LCP Data:
    //          1 - Authentication-Protocol:
    //              Type: 3 (Authentication-Protocol)
    //              Length: 4 (Size of option)
    //              Authentication-Protocol: 0xC023 (Password Authentication Protocol)
    LCP_PACKET* lcp_packet = (LCP_PACKET*) buffer;
    LCP_OPTION_AUTH_PAP* lcp_option_auth = (LCP_OPTION_AUTH_PAP*) lcp_packet->data;
    // write option data
    lcp_option_auth->type = LCP_TYPE_AUTHENTICATION;
    lcp_option_auth->length = sizeof(LCP_OPTION_AUTH_PAP);
    lcp_option_auth->auth_proto = LCP_AUTH_PROTO_PAP;
    // write header
    lcp_packet->header.code = LCP_CODE_CONFIG_REQUEST;
    lcp_packet->header.identifier = 1;
    lcp_packet->header.length = sizeof(LCP_HEADER) + sizeof(LCP_OPTION_AUTH_PAP);
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
    // send PAP AUTHENTICATION REQUEST packet
    //
    // PAP AUTHENTICATION REQUEST FORMAT
    //      (RFC 1334) - Section 2.2.1 Authenticate-Request
    //      PAP Header:
    //          Code: 1 (Authenticate-Request)
    //      PAP Data:
    //          Peer-ID Length: indicates the length of the Peer-ID field
    //          Peer-ID: zero or more octets and indicates the name of the peer to be authenticated
    //          Passwd-Length: indicates the length of the Password field
    //          Password: zero or more octets and indicates the password to be used for authentication

    PAP_PACKET* pap_packet = (PAP_PACKET*) buffer;
    // write value size
    pap_packet->data[0] = strlen(peer_id);
    memcpy(pap_packet->data+1, peer_id, strlen(peer_id));
    pap_packet->data[1+strlen(peer_id)] = strlen(passwd);
    memcpy(pap_packet->data+1+strlen(peer_id)+1, passwd, strlen(passwd));
    // write header
    pap_packet->header.code = PAP_CODE_AUTH_REQUEST;
    pap_packet->header.length = sizeof(PAP_HEADER) + 1 + strlen(peer_id) + 1 + strlen(passwd);
    // send packet
    net_sendn(auth_fd, (char*) pap_packet, pap_packet->header.length);
    printf("[*] send RESPONSE packet!\n");

    //
    //  receive response
    //
    if (pap_recv_packet(auth_fd, pap_packet))
    {
        printf("[!] PACKET -> not expected\n");
        return;
    }
    if (pap_packet->header.code == PAP_CODE_ACK)
    {
        printf("[+] Authenticated -> success\n");
        printf("\tMessage: ");
        for (int i=0; i<pap_packet->data[0]; i++)
            printf("%c", pap_packet->data[1+i]);
        printf("\n");
    }
        
    else
        if (pap_packet->header.code == PAP_CODE_NAK)
        {
            printf("[-] Authenticated -> fail\n");
            printf("\tMessage: ");
            for (int i=0; i<pap_packet->data[0]; i++)
                printf("%c", pap_packet->data[1+i]);
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
    LCP_OPTION_AUTH_PAP* lcp_option_auth = (LCP_OPTION_AUTH_PAP*) lcp_packet->data;
    printf("[*] got CONFIG_REQUEST:\n\tType: %u\n\tLength: %u\n\tProtocol: 0x%X\n",
        lcp_option_auth->type,
        lcp_option_auth->length,
        lcp_option_auth->auth_proto
    );

    //
    // Check and response configuration
    //
    if (lcp_option_auth->type != LCP_TYPE_AUTHENTICATION ||
        lcp_option_auth->auth_proto != LCP_AUTH_PROTO_PAP)
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
    // receive AUTHENTICATION REQUEST
    //
    PAP_PACKET* pap_packet = (PAP_PACKET*) buffer;
    if (pap_recv_packet(peer_fd, pap_packet) ||
        pap_packet->header.code != PAP_CODE_AUTH_REQUEST)
    {
        printf("[!] PACKET -> not expected!\n");
        return;
    }
    PAP_REQUEST_DATA pap_request_data;
    pap_parse_packet(pap_packet, PAP_CODE_AUTH_REQUEST, &pap_request_data);
    printf("[+] got AUTHENTICATION_REQUEST\n\tPEER_ID: ");
    for (int i=0; i<pap_request_data.peer_id_length; i++)
        printf("%c",pap_request_data.peer_id[i]);
    printf("\n\tPASSWD: ");
    for (int i=0; i<pap_request_data.password_length; i++)
        printf("%c",pap_request_data.password[i]);
    printf("\n");
    
    //
    // compare and response
    //
    if (strncmp(peer_id, pap_request_data.peer_id, strlen(peer_id))==0 &&
        strncmp(passwd, pap_request_data.password, strlen(passwd))==0)
    // send PAP ACK packet
    //      (RFC 1334) - Section 2.2.2  Authenticate-Ack and Authenticate-Nak
    //      PAP Header:
    //          Code: 2 (Authenticate-Ack)
    //      PAP Data:
    //          Msg-Length: indicates the length of the Message field
    //          Message: zero or more octets, and its contents are implementation dependent.
    //              It is intended to be human readable, and MUST NOT affect operation of the protocol
    {
        printf("[+] Authenticated!\n");
        pap_packet->data[0] = 2;
        memcpy(pap_packet->data+1, "OK", 2);
        pap_packet->header.code = PAP_CODE_ACK;
        pap_packet->header.length = sizeof(PAP_HEADER) + 1 + 2;
        net_sendn(peer_fd, (char*) pap_packet, pap_packet->header.length);
    }
    else
    // send PAP NAK packet
    //      (RFC 1334) - Section 2.2.2  Authenticate-Ack and Authenticate-Nak
    //      PAP Header:
    //          Code: 3 (Authenticate-Nak)
    //      PAP Data:
    //          Msg-Length: indicates the length of the Message field
    //          Message: zero or more octets, and its contents are implementation dependent.
    //              It is intended to be human readable, and MUST NOT affect operation of the protocol
    {
        printf("[-] Not recognized!\n");
        pap_packet->data[0] = 4;
        memcpy(pap_packet->data+1, "FAIL", 4);
        pap_packet->header.code = PAP_CODE_NAK;
        pap_packet->header.length = sizeof(PAP_HEADER) + 1 + 4;
        net_sendn(peer_fd, (char*) pap_packet, pap_packet->header.length);
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



