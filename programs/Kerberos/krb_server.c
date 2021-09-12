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
 *           Client <--------------------- SS Server  --'
 **/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <pthread.h>

#include "library/net.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/aes.h"

#include "library/aes.h"
#include "krb.h"

int TGS_keynum = 0;
Key TGS_Keys[100];
ID TGS_Key_ID[100];
int SS_keynum = 0;
Key SS_Keys[100];
ID SS_Key_ID[100];

bool halt=false;
mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_aes_context aes;

void init()
{
    int ret;

    //
    // Setup the RNG
    //
    printf("[*] Seeding random number generator\n");
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0)) != 0)
    {
        printf("\t[!] mbedtls_ctr_drbg_seed returned %d\n", ret);
        exit(EXIT_FAILURE);
    }

    //
    // Init AES
    //
    mbedtls_aes_init(&aes);
}

void new_TGS_SessionKey(char *dest, ID id)
{
    mbedtls_ctr_drbg_random(&ctr_drbg, dest, sizeof(Key));
    memcpy(TGS_Keys[TGS_keynum], dest, sizeof(Key));
    TGS_Key_ID[TGS_keynum] = id;
    TGS_keynum++;
}
void new_SS_SessionKey(char *dest, ID id)
{
    mbedtls_ctr_drbg_random(&ctr_drbg, dest, sizeof(Key));
    memcpy(SS_Keys[SS_keynum], dest, sizeof(Key));
    SS_Key_ID[SS_keynum] = id;
    SS_keynum++;
}

void as_handler(int client_fd, struct sockaddr_in* client_addr)
{
    Key encrypt_key, temp;
    printf("\n[AS] got connect from %s\n", inet_ntoa(client_addr->sin_addr));

    //
    // Receive authentication request
    //
    AS_REQUEST as_request;
    if (net_recvn(client_fd, (char*) &as_request, sizeof(AS_REQUEST)) != sizeof(AS_REQUEST))
    {
        printf("\t[AS !] Recv AS_REQUEST -> fail\n");
        return;
    }
    printf("[AS +] Recv AS_REQUEST\n");

    //
    // Check user_id
    //
    printf("[AS *] Check user_id\n");
    int id=-1;
    for (int i=0; i<sizeof(user_num); i++)
        if (user_id[i] == as_request.id)
        {
            printf("[AS +] Found ID: %d\n", i);
            id = i;
        }
    if (id == -1)
    {
        printf("\t[AS !] UserID not found!\n");
        return;
    }

    AS_RESPONSE as_response;
    Key new_tgs_key;
    // Generate MessageA = encrypt(SessionKey, secret=UserPass)
    printf("[AS *] Generate MessageA\n");
    //      Make TGS SessionKey
    new_TGS_SessionKey(new_tgs_key, id);
    memcpy(as_response.message_a.session_key, new_tgs_key, sizeof(Key));
    printf("\t[AS *] Gen TGS_SessionKey: ");
    for (int i=0; i<sizeof(Key); i++)
        printf("%02X", as_response.message_a.session_key[i]);
    printf("\n");
    //      Encrypt SessionKey
    memset(encrypt_key, 0, sizeof(Key));
    memcpy(encrypt_key, user_pass[id], strlen(user_pass[id]));
    aes_encrypt(&aes, encrypt_key, 16, &as_response.message_a, &as_response.message_a);

    // Generate MessageB = encrypt(SessionKey + UserID + Address + Validity, secret=TGS_KEY)
    printf("[AS *] Generate MessageB\n");
    memcpy(as_response.message_b.session_key, new_tgs_key, sizeof(Key));
    as_response.message_b.client_info.id = id;
    as_response.message_b.client_info.sin_addr = client_addr->sin_addr;
    as_response.message_b.client_info.validity.timestamp = time(NULL);
    as_response.message_b.client_info.validity.duration = 3600;
    //      Encrypt client_info using TGS secret
    memset(encrypt_key, 0, sizeof(Key));
    memcpy(encrypt_key, TGS_KEY, sizeof(Key));
    aes_encrypt(&aes, encrypt_key, 16, &as_response.message_b, &as_response.message_b);
    // Send response
    if (net_sendn(client_fd, (char*) &as_response, sizeof(AS_RESPONSE)) != sizeof(AS_RESPONSE))
    {
        printf("[AS !] Send AS_RESPONSE -> fail\n");
        return;
    };
    printf("[AS +] Send AS_RESPONSE\n");
}
void tgs_handler(int client_fd, struct sockaddr_in* client_addr)
{
    Key TGS_SessionKey;
    //
    // Receive service authorization request
    //
    TGS_REQUEST tgs_request;
    if (net_recvn(client_fd, (char*) &tgs_request, sizeof(TGS_REQUEST)) != sizeof(TGS_REQUEST))
    {
        printf("\t[TGS !] Recv TGS_REQUEST -> fail\n");
        return;
    }
    printf("[TGS +] Recv TGS_REQUEST\n");
    
    //
    // Check UserID to get SessionKey
    //
    // Decrypt MessageC to get SessionKey
    aes_decrypt(&aes, TGS_KEY, sizeof(Key), &tgs_request.message_c.message, &tgs_request.message_c.message);
    printf("[TGS +] Get SessionKey: ");
    for (int i=0; i<sizeof(Key); i++)
        printf("%02X", tgs_request.message_c.message.session_key[i]);
    printf("\n");
    memcpy(TGS_SessionKey, tgs_request.message_c.message.session_key, sizeof(Key));

    // Decrypt MessageD
    aes_decrypt(&aes, TGS_SessionKey, sizeof(Key), &tgs_request.message_d, &tgs_request.message_d);
    // Check validity
    uint32_t secret_start = (uint32_t) tgs_request.message_c.message.client_info.validity.timestamp;
    uint32_t secret_end = secret_start + (uint32_t) tgs_request.message_c.message.client_info.validity.duration;
    uint32_t now = (uint32_t) time(NULL);
    uint32_t client_time = (uint32_t) tgs_request.message_d.timestamp;
    if (!(secret_start <= now && secret_end>=now && client_time<=now && client_time>=secret_start))
    {
        printf("[TGS !] timestamp not valid!\n");
        return;
    }
    if (tgs_request.message_d.id != tgs_request.message_c.message.client_info.id)
    {
        printf("TGS !] UserID not match\n");
    }
    printf("[TGS +] Authorization valid\n");

    //
    // Send response
    //
    TGS_RESPONSE tgs_response;
    Key new_ss_key;
    // Generate MessageF = encrypt(SS_SessionKey, secret=TGS_SessionKey)
    //      Make SS_SessionKey
    new_SS_SessionKey(new_ss_key, tgs_request.message_c.message.client_info.id);
    memcpy(tgs_response.message_f.session_key, new_ss_key, sizeof(Key));
    printf("\t[TGS *] Gen SS_SessionKey: ");
    for (int i=0; i<sizeof(Key); i++)
        printf("%02X", tgs_response.message_f.session_key[i]);
    printf("\n");
    //      Encrypt MessageF
    aes_encrypt(&aes, TGS_SessionKey, sizeof(Key), &tgs_response.message_f, &tgs_response.message_f);
    
    // Generate MessageE = encrypt(SS_SessionKey + UserID + Address + Validity, secret=SS_KEY)
    memcpy(&tgs_response.message_e, &tgs_request.message_c.message, sizeof(struct _MESSAGE_B));
    memcpy(&tgs_response.message_e.session_key, new_ss_key, sizeof(Key));
    //      Encrypt MessageE
    aes_encrypt(&aes, SS_KEY, sizeof(Key), &tgs_response.message_e, &tgs_response.message_e);

    // Send
    if (net_sendn(client_fd, &tgs_response, sizeof(TGS_RESPONSE)) != sizeof(TGS_RESPONSE))
    {
        printf("[TGS !] Send TGS_RESPONSE -> fail\n");
        return;
    };
    printf("[TGS +] Send TGS_RESPONSE\n");

}
void ss_handler(int client_fd, struct sockaddr_in* client_addr)
{
    Key SS_SessionKey;
    //
    // Receive service request
    //
    SS_REQUEST ss_request;
    if (net_recvn(client_fd, (char*) &ss_request, sizeof(SS_REQUEST)) != sizeof(SS_REQUEST))
    {
        printf("\t[SS !] Recv SS_REQUEST -> fail\n");
        return;
    }
    printf("[SS +] Recv SS_REQUEST\n");
    
    //
    // Check UserID to get SessionKey
    //
    // Decrypt MessageE to get SessionKey
    aes_decrypt(&aes, SS_KEY, sizeof(Key), &ss_request.message_e, &ss_request.message_e);
    printf("[SS +] Get SessionKey: ");
    for (int i=0; i<sizeof(Key); i++)
        printf("%02X", ss_request.message_e.session_key[i]);
    printf("\n");
    memcpy(SS_SessionKey, ss_request.message_e.session_key, sizeof(Key));

    // Decrypt MessageG
    aes_decrypt(&aes, SS_SessionKey, sizeof(Key), &ss_request.message_g, &ss_request.message_g);
    // Check validity
    uint32_t secret_start = (uint32_t) ss_request.message_e.client_info.validity.timestamp;
    uint32_t secret_end = secret_start + (uint32_t) ss_request.message_e.client_info.validity.duration;
    uint32_t now = (uint32_t) time(NULL);
    uint32_t client_time = (uint32_t) ss_request.message_g.timestamp;
    if (!(secret_start <= now && secret_end>=now && client_time<=now && client_time>=secret_start))
    {
        printf("[SS !] timestamp not valid!\n");
        return;
    }
    if (ss_request.message_g.id != ss_request.message_e.client_info.id)
    {
        printf("SS !] UserID not match\n");
    }
    printf("[SS +] Authorization valid\n");

    //
    // Send response
    //
    SS_RESPONSE ss_response = {
        .timestamp = time(NULL)
    };
    //      Encrypt MessageH
    aes_encrypt(&aes, SS_SessionKey, sizeof(Key), &ss_response, &ss_response);

    // Send
    if (net_sendn(client_fd, &ss_response, sizeof(SS_RESPONSE)) != sizeof(SS_RESPONSE))
    {
        printf("[SS !] Send SS_RESPONSE -> fail\n");
        return;
    };
    printf("[SS +] Send SS_RESPONSE\n");
}
void* as_main()
{
    net_tcp_server(DEFAULT_ADDR, AS_PORT, as_handler, &halt);
}
void* tgs_main()
{
    net_tcp_server(DEFAULT_ADDR, TGS_PORT, tgs_handler, &halt);
}
void* ss_main()
{
    net_tcp_server(DEFAULT_ADDR, SS_PORT, ss_handler, &halt);
}

int main(int argc, char* argv[])
{
    init();
    pthread_t thread_as;
    pthread_create(&thread_as, NULL, as_main, NULL);
    
    pthread_t thread_tgs;
    pthread_create(&thread_tgs, NULL, tgs_main, NULL);
    
    pthread_t thread_ss;
    pthread_create(&thread_ss, NULL, ss_main, NULL);
    
    pthread_join(thread_as, NULL);
    pthread_join(thread_tgs, NULL);
    pthread_join(thread_ss, NULL);
    return 0;
}



