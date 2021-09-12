/**
 * Author:    Le Thieu Bao (https://github.com/lebaoworks)
 * Created:   10.09.2021
 * 
 * Demonstration of Kerberos authentication scheme.
 * 
 * Basic flow:      
 * 
 *                           UserID
 *            Client ---------------------> AS Server ---.
 *                                                       | if UserID is in database,
 *                                                       |     Generate MessageA by encrypt SessionKey using UserPassword
 *                                                       |     Generate MessageB by encrypt Ticket-Granting-Ticket
 *                                                       |          (Key+UserID+Address+Validity) using TGS secret
 *                      MessageA, MessageB               |         
 *        .-- Client <--------------------- AS Server <--'
 *        | 
 *        | Decrypted MessageA to get SessionKey
 *        | Generate MessageC by compose MessageB with ID of requested service 
 *        | Generate MessageD by encrypt (UserID, timestamp) using SessionKey
 *        |            MessageC, MessageD            
 *        '-> Client ---------------------> TGS Server --.
 *                                                       | use TGS_KEY decrypt MessageC to get TGS_SessionKey 
 *                                                       | use TGS_SessionKey decrypt MessageD to get UserID and timestamp
 *                                                       | validify UserID and timestamp
 *                                                       | Generate MessageE by encrypt (SS_SessionKey+UserID+Address+Validity)
 *                                                       |      with SS secret
 *                       MessageE, MessageF              | Generate MessageF by encrypt SS_SessionKey with TGS_SessionKey
 *        .-- Client <--------------------- TGS Server --'
 *        | 
 *        | Decrypted MessageF to get SessionKey
 *        | Generate MessageG by encrypt (UserID, timestamp) using SS_SessionKey
 *        |            MessageE, MessageG            
 *        '-> Client ---------------------> SS Server --.
 *                                                      | use SS secret decrypt MessageE to get SS_SessionKey 
 *                                                      | use SS_SessionKey decrypt MessageG to get UserID and timestamp
 *                                                      | validify UserID and timestamp
 *                       MessageH                       | Generate MessageH by encrypt timestamp with SS_SessionKey
 *           Client <--------------------- TGS Server --'
 **/


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>

#include "library/net.h"
#include "library/aes.h"
#include "mbedtls/aes.h"

#include "krb.h"

#define USERID 1

mbedtls_aes_context aes;

AS_RESPONSE as_response;
TGS_REQUEST tgs_request;
TGS_RESPONSE tgs_response;
SS_REQUEST ss_request;
SS_RESPONSE ss_response;


void init()
{
    //
    // Init AES
    //
    mbedtls_aes_init(&aes);
}

void as_handler(int server_fd)
{
    //
    // Send authentication request
    //
    AS_REQUEST as_request = {.id = USERID};
    net_sendn(server_fd, (char*) &as_request, sizeof(AS_REQUEST));

    //
    // Receive response
    //
    net_recvn(server_fd, (char*) &as_response, sizeof(AS_RESPONSE));
    printf("[+] Recv AS_RESPONSE\n");

    // Export SessionKey
    Key key;
    memset(key, 0, sizeof(Key));
    memcpy(key, user_pass[USERID], strlen(user_pass[USERID]));
    aes_decrypt(&aes, key, 16, (char*) &as_response.message_a, (char*) &as_response.message_a);
    printf("[+] Got TGS_SessionKey: ");
    for (int i=0; i<sizeof(Key); i++)
        printf("%02X", as_response.message_a.session_key[i]);
    printf("\n");
}
void tgs_handler(int server_fd)
{
    Key TGS_SessionKey;
    memcpy(TGS_SessionKey, as_response.message_a.session_key, sizeof(Key));

    //
    // Send Service Authorization
    //
    //      Generate MessageC
    memcpy(&tgs_request.message_c.message, &as_response.message_b, sizeof(struct _MESSAGE_B));
    tgs_request.service_id = SERVICE_A;
    //      Generate MessageD
    tgs_request.message_d.id = USERID;
    tgs_request.message_d.timestamp = time(NULL);
    aes_encrypt(&aes, TGS_SessionKey, sizeof(Key), (char*) &tgs_request.message_d, (char*) &tgs_request.message_d);
    //      Send
    net_sendn(server_fd, (char*) &tgs_request, sizeof(TGS_REQUEST));

    //
    // Receive Response
    //
    net_recvn(server_fd, (char*) &tgs_response, sizeof(TGS_RESPONSE));
    Key SS_SessionKey;
    aes_decrypt(&aes, TGS_SessionKey, sizeof(Key), (char*) &tgs_response.message_f, (char*) &tgs_response.message_f);
    printf("[+] Got SS_SessionKey: ");
    for (int i=0; i<sizeof(Key); i++)
        printf("%02X", tgs_response.message_f.session_key[i]);
    printf("\n");
}
void ss_handler(int server_fd)
{
    Key SS_SessionKey;
    memcpy(SS_SessionKey, tgs_response.message_f.session_key, sizeof(Key));

    //
    // Send Service Request
    //
    //      Generate MessageE
    memcpy(&ss_request.message_e, &tgs_response.message_e, sizeof(struct _MESSAGE_E));
    ss_request.service_id = SERVICE_A;
    //      Generate MessageG
    ss_request.message_g.id = USERID;
    ss_request.message_g.timestamp = time(NULL);
    aes_encrypt(&aes, SS_SessionKey, sizeof(Key), (char*) &ss_request.message_g, (char*) &ss_request.message_g);
    //      Send
    net_sendn(server_fd, (char*) &ss_request, sizeof(SS_REQUEST));

    //
    // Receive Response
    //
    net_recvn(server_fd, (char*) &ss_response, sizeof(SS_RESPONSE));
    aes_decrypt(&aes, SS_SessionKey, sizeof(Key), (char*) &ss_response, (char*) &ss_response);
    printf("[+] Got timestamp: %d\n", (int) ss_response.timestamp);
    printf("\n");
}
int main(void)
{
    init();
    int fd;
    // Handle AS
    fd = net_tcp_connect(DEFAULT_ADDR, AS_PORT);
    if (fd != -1)
        as_handler(fd);
    else
    {
        printf("[!] Can not connect to AS!\n");
        exit(EXIT_FAILURE);
    }
    close(fd);

    // Handle TGS
    fd = net_tcp_connect(DEFAULT_ADDR, TGS_PORT);
    if (fd != -1)
        tgs_handler(fd);
    else
    {
        printf("[!] Can not connect to TGS!\n");
        exit(EXIT_FAILURE);
    }
    close(fd);

    // Handle SS
    fd = net_tcp_connect(DEFAULT_ADDR, SS_PORT);
    if (fd != -1)
        ss_handler(fd);
    else
    {
        printf("[!] Can not connect to SS!\n");
        exit(EXIT_FAILURE);
    }
    close(fd);
    return 0;
}
