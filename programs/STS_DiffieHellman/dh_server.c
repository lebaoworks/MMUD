/**
 * Author:    Le Thieu Bao (https://github.com/lebaoworks)
 * Created:   10.09.2021
 * 
 * Demonstration of Diffie-Hellman key exchange
 *      Documentation: https://www.ietf.org/rfc/rfc5246.txt
 * 
 * Basic flow:
 *      P: modulus
 *      G: primitive root modulo of P
 *      Ys/Yc: Server public/Client public
 *      Xs/Xc: Server secret/Client secret
 *      
 * 
 *                      (P, G, Ys) - Signed
 *        .--- Client <--------------------- Server
 *        | Verify sign
 *        | Generate secret Xc
 *        | Derive shared secret: K = Ys ^ Xc mod P
 *        |    
 *        v            Yc = G ^ Xc mod P
 *        '-- Client ---------------------> Server ---.
 *                                                    | Derive shared secret: K = Yc ^ Xs mod P
 *                      Encrypted Message             | Encrypt message using shared secret
 *        .-- Client <--------------------- Server <--'
 *        | Decrypted message
 *        |  using shared secret
 *        v
 *      
 **/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "library/net.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/sha1.h"
#include "mbedtls/rsa.h"
#include "mbedtls/aes.h"
#include "mbedtls/dhm.h"

/*
 * Note: G = 4 is always a quadratic residue mod P,
 * so it is a generator of order Q (with P = 2*Q+1).
 */
#define GENERATOR "4"
#define PRIME_BITS 2048

#define KEY_SIZE 2048
#define EXPONENT 65537
#define RSA_PRIV_KEY_FILE "rsa_priv.txt"
#define RSA_PUB_KEY_FILE "rsa_pub.txt"
#define DH_PRIME_FILE "dh_prime.txt"

bool halt=false;
mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_rsa_context rsa;
mbedtls_dhm_context dhm;
mbedtls_aes_context aes;

void init()
{
    int ret;
    FILE* f;
    mbedtls_mpi D, E, G, N, P, Q, DP, DQ, QP;
    mbedtls_mpi_init(&D);
    mbedtls_mpi_init(&E);
    mbedtls_mpi_init(&G);
    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&P);
    mbedtls_mpi_init(&Q);
    mbedtls_mpi_init(&DP);
    mbedtls_mpi_init(&DQ);
    mbedtls_mpi_init(&QP);

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
    // Setup RSA key
    //
    mbedtls_rsa_init(&rsa);
    printf("[*] Reading private key from %s\n", RSA_PRIV_KEY_FILE);
    if ((f = fopen(RSA_PRIV_KEY_FILE, "rb")) == NULL)
    {
        // Generate RSA keys
        printf("\t[-] Not found %s!\n", RSA_PRIV_KEY_FILE);
        printf("\t[*] Generating RSA keys\n");
        if ((ret = mbedtls_rsa_gen_key(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg, KEY_SIZE, EXPONENT)) != 0)
        {
            printf("\t\t[!] mbedtls_rsa_gen_key returned %d\n", ret);
            exit(EXIT_FAILURE);
        }
        // Export RSA keys
        printf("\t[*] Exporting RSA keys\n");
        if ((ret = mbedtls_rsa_export(&rsa, &N, &P, &Q, &D, &E)) != 0 ||
            (ret = mbedtls_rsa_export_crt(&rsa, &DP, &DQ, &QP)) != 0)
        {
            printf("\t\t[!] failed to export RSA parameters\n");
            exit(EXIT_FAILURE);
        }
        // Export public key
        printf("\t\t[*] Writting RSA public key\n");
        if ((f = fopen(RSA_PUB_KEY_FILE, "wb+")) == NULL)
        {
            printf("\t\t\t[!] failed to open %s for writing\n", RSA_PUB_KEY_FILE);
            exit(EXIT_FAILURE);
        }
        if ((ret = mbedtls_mpi_write_file("N = ", &N, 16, f)) != 0 ||
            (ret = mbedtls_mpi_write_file("E = ", &E, 16, f)) != 0)
        {
            printf("\t\t\t[!] mbedtls_mpi_write_file returned %d\n", ret);
            exit(EXIT_FAILURE);
        }
        fclose(f);
        // Export private key
        printf("\t\t[*] Writting RSA private key\n");
        if ((f = fopen(RSA_PRIV_KEY_FILE, "wb+")) == NULL)
        {
            printf("\t\t\t[!] failed to open %s for writing\n", RSA_PRIV_KEY_FILE);
            exit(EXIT_FAILURE);
        }
        if ((ret = mbedtls_mpi_write_file("N = ", &N, 16, f)) != 0 ||
            (ret = mbedtls_mpi_write_file("E = ", &E, 16, f)) != 0 ||
            (ret = mbedtls_mpi_write_file("D = ", &D, 16, f)) != 0 ||
            (ret = mbedtls_mpi_write_file("P = ", &P, 16, f)) != 0 ||
            (ret = mbedtls_mpi_write_file("Q = ", &Q, 16, f)) != 0 ||
            (ret = mbedtls_mpi_write_file("DP = ", &DP, 16, f)) != 0 ||
            (ret = mbedtls_mpi_write_file("DQ = ", &DQ, 16, f)) != 0 ||
            (ret = mbedtls_mpi_write_file("QP = ", &QP, 16, f)) != 0)
        {
            printf("\t\t\t[!] mbedtls_mpi_write_file returned %d\n", ret);
            exit(EXIT_FAILURE);
        }
        fclose(f);
    }
    else
    {
        // Read parameters
        if ((ret = mbedtls_mpi_read_file(&N, 16, f)) != 0 ||
            (ret = mbedtls_mpi_read_file(&E, 16, f)) != 0 ||
            (ret = mbedtls_mpi_read_file(&D, 16, f)) != 0 ||
            (ret = mbedtls_mpi_read_file(&P, 16, f)) != 0 ||
            (ret = mbedtls_mpi_read_file(&Q, 16, f)) != 0)
        {
            printf("\t[!] mbedtls_mpi_read_file returned %d\n", ret);
            fclose(f);
            exit(EXIT_FAILURE);
        }
        fclose(f);

        if ((ret = mbedtls_rsa_import(&rsa, &N, &P, &Q, &D, &E)) != 0)
        {
            printf("\t[!] mbedtls_rsa_import returned %d\n", ret);
            exit(EXIT_FAILURE);
        }
        if ((ret = mbedtls_rsa_complete(&rsa)) != 0)
        {
            printf("\t[!] mbedtls_rsa_complete returned %d\n", ret);
            exit(EXIT_FAILURE);
        }
    }

    //
    // Setup Diffie-Hellman modulus and generator
    //
    mbedtls_dhm_init(&dhm);
    printf("[*] Reading DH parameters from %s\n", DH_PRIME_FILE);
    if ((f = fopen(DH_PRIME_FILE, "rb")) == NULL)
    {
        // Generate prime
        printf("\t[-] Not found %s!\n", DH_PRIME_FILE);
        printf("\t[*] Generating DH prime, large prime may takes minutes!\n");
        if ((ret = mbedtls_mpi_read_string(&G, 10, GENERATOR)) != 0)
        {
            printf("\t\t[!] mbedtls_mpi_read_string returned %d\n", ret);
            exit(EXIT_FAILURE);
        }
        if ((ret = mbedtls_mpi_gen_prime(&P, PRIME_BITS, 1, mbedtls_ctr_drbg_random, &ctr_drbg)) != 0)
        {
            printf("\t\t[!] mbedtls_mpi_gen_prime returned %d\n\n", ret);
            exit(EXIT_FAILURE);
        }
        printf("\t\t[*] Verifying Q = (P-1)/2 is prime\n");
        if ((ret = mbedtls_mpi_sub_int(&Q, &P, 1)) != 0)
        {
            printf("\t\t\t[!] mbedtls_mpi_sub_int returned %d\n", ret);
            exit(EXIT_FAILURE);
        }
        if ((ret = mbedtls_mpi_div_int(&Q, NULL, &Q, 2)) != 0)
        {
            printf("\t\t\t[!] mbedtls_mpi_div_int returned %d\n", ret);
            exit(EXIT_FAILURE);
        }
        if ((ret = mbedtls_mpi_is_prime_ext(&Q, 50, mbedtls_ctr_drbg_random, &ctr_drbg)) != 0)
        {
            printf("\t\t\t[!] mbedtls_mpi_is_prime returned %d\n", ret);
            exit(EXIT_FAILURE);
        }
        // Export prime
        printf("\t[*] Exporting prime\n");
        if ((f = fopen(DH_PRIME_FILE, "wb+")) == NULL)
        {
            printf("\t\t[!] failed to open %s for writing\n", DH_PRIME_FILE);
            exit(EXIT_FAILURE);
        }
        if ((ret = mbedtls_mpi_write_file("P = ", &P, 16, f) != 0) ||
            (ret = mbedtls_mpi_write_file("G = ", &G, 16, f) != 0))
        {
            printf("\t\t[!] mbedtls_mpi_write_file returned %d\n", ret);
            fclose(f);
            exit(EXIT_FAILURE);
        }
        fclose(f);
        mbedtls_mpi_copy(&dhm.MBEDTLS_PRIVATE(P), &P);
        mbedtls_mpi_copy(&dhm.MBEDTLS_PRIVATE(G), &G);
    }
    else
    {
        if (mbedtls_mpi_read_file(&dhm.MBEDTLS_PRIVATE(P), 16, f) != 0 ||
            mbedtls_mpi_read_file(&dhm.MBEDTLS_PRIVATE(G), 16, f) != 0)
        {
            printf("\t[!] Invalid DH parameter file\n");
            fclose(f);
            exit(EXIT_FAILURE);
        }
        fclose(f);
    }

    //
    // Init AES
    //
    mbedtls_aes_init(&aes);
}

void auth_handler(int client_fd, struct sockaddr_in* client_addr)
{
    printf("\n*====================*\n[*] got connect from %s\n", inet_ntoa(client_addr->sin_addr));

    int ret;
    size_t n;
    uint8_t buf[2048];
    uint8_t hash[20];

    //
    // Setup the DH parameters (P, G, Ys)
    //
    printf("[*] Setup Diffie-Hellman parameters\n");
    memset(buf, 0, sizeof(buf));
    if ((ret = mbedtls_dhm_make_params(
        &dhm, (int) mbedtls_mpi_size(&dhm.MBEDTLS_PRIVATE(P)),
        buf, &n,
        mbedtls_ctr_drbg_random, &ctr_drbg)) != 0)
    {
        printf("\t[!] mbedtls_dhm_make_params returned %d\n", ret);
        exit(EXIT_FAILURE);
    }

    //
    // Sign the parameters and send them
    //
    printf("[*] Sign Diffie-Hellman parameters\n");
    if ((ret = mbedtls_sha1(buf, n, hash)) != 0)
    {
        printf("\t[!] mbedtls_sha1 returned %d\n", ret);
        exit(EXIT_FAILURE);
    }
    buf[n]   = (unsigned char)(rsa.MBEDTLS_PRIVATE(len) >> 8);
    buf[n+1] = (unsigned char)(rsa.MBEDTLS_PRIVATE(len));
    if ((ret = mbedtls_rsa_pkcs1_sign(
        &rsa,
        mbedtls_ctr_drbg_random, &ctr_drbg,
        MBEDTLS_MD_SHA1, 20, hash,
        buf+n+2)) != 0)
    {
        printf("[!] mbedtls_rsa_pkcs1_sign returned %d\n", ret);
        exit(EXIT_FAILURE);
    }

    printf("[*] Sending DH parameters\n");
    int buflen = n + 2 + rsa.MBEDTLS_PRIVATE(len);
    if ((ret = net_sendn(client_fd, (char*) &buflen, 2)) != 2 ||
        (ret = net_sendn(client_fd, buf, buflen)) != buflen)
    {
        printf("\t[!] net_sendn returned %d\n", ret);
        exit(EXIT_FAILURE);
    }

    //
    // Get client's public value: Yc = G ^ Xc mod P
    //
    printf("[*] Receiving client's public value\n");
    n = mbedtls_dhm_get_len(&dhm);
    if ((ret = net_recvn(client_fd, buf, n)) != n)
    {
        printf("\t[!] net_recvn returned %d\n", ret);
        exit(EXIT_FAILURE);
    }
    if ((ret = mbedtls_dhm_read_public(&dhm, buf, n)) != 0)
    {
        printf("\t[!] mbedtls_dhm_read_public returned %d\n", ret);
        exit(EXIT_FAILURE);
    }

    //
    // Derive the shared secret: K = Yc ^ Xs mod P
    //
    printf("[*] Shared secret: ");
    if ((ret = mbedtls_dhm_calc_secret(
        &dhm,
        buf, sizeof(buf), &n,
        mbedtls_ctr_drbg_random, &ctr_drbg)) != 0)
    {
        printf("\n\t[!] mbedtls_dhm_calc_secret returned %d\n", ret);
        exit(EXIT_FAILURE);
    }
    for (int i=0; i<16; i++)
        printf("%02x", buf[i]);
    printf("\n");

    //
    // Send message using shared secret
    //
    printf("[*] Encrypting and sending the ciphertext\n");
    mbedtls_aes_setkey_enc(&aes, buf, 256);
    memcpy(buf, "BAO BAO BAO BAO", 16);
    mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, buf, buf);

    if ((ret = net_sendn(client_fd, buf, 16)) != 16)
    {
        printf("\t[!] net_send returned %d\n", ret);
        exit(EXIT_FAILURE);
    }
}
int main(int argc, char* argv[])
{
    init();
    net_tcp_server(DEFAULT_ADDR, DEFAULT_PORT, auth_handler, &halt);
    return 0;
}



