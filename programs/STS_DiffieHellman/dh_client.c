/**
 * Author:    Le Thieu Bao (https://github.com/lebaoworks)
 * Created:   07.09.2021
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

#define RSA_PUB_KEY_FILE "rsa_pub.txt"

mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_rsa_context rsa;
mbedtls_dhm_context dhm;
mbedtls_aes_context aes;

void init()
{
    int ret;
    FILE* f;

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
    // Read RSA public key
    //
    mbedtls_rsa_init(&rsa);
    printf("[*] Reading public key from %s\n", RSA_PUB_KEY_FILE);
    if ((f = fopen(RSA_PUB_KEY_FILE, "rb")) == NULL)
    {
        printf("\t[-] Not found %s!\n", RSA_PUB_KEY_FILE);
        exit(EXIT_FAILURE);
    }
    else
    {
        if ((ret = mbedtls_mpi_read_file(&rsa.MBEDTLS_PRIVATE(N), 16, f)) != 0 ||
            (ret = mbedtls_mpi_read_file(&rsa.MBEDTLS_PRIVATE(E), 16, f)) != 0)
        {
            printf("\t[!] mbedtls_mpi_read_file returned %d\n", ret);
            fclose(f);
            exit(EXIT_FAILURE);
        }
        fclose(f);
        rsa.MBEDTLS_PRIVATE(len) = (mbedtls_mpi_bitlen(&rsa.MBEDTLS_PRIVATE(N)) + 7) >> 3;
    }

    //
    // init Diffie-Hellman
    //
    mbedtls_dhm_init(&dhm);

    //
    // Init AES
    //
    mbedtls_aes_init(&aes);
}

void peer_handler(int server_fd)
{
    int ret, n;
    uint8_t buf[2048];
    uint8_t hash[20];

    //
    // Receive total_len, DH params (P, G, Ys), modulus_len, sign
    //
    printf("[*] Receiving DH parameters\n");
    int buflen = 0;
    if ((ret = net_recvn(server_fd, (char*) &buflen, 2)) != 2)
    {
        printf("\t[!] net_recvn returned %d\n", ret);
        exit(EXIT_FAILURE);
    }
    if ((ret = net_recvn(server_fd, buf, buflen)) != buflen)
    {
        printf("\t[!] net_recvn returned %d\n", ret);
        exit(EXIT_FAILURE);
    }

    unsigned char *p = buf, *end = buf + buflen;
    if ((ret = mbedtls_dhm_read_params(&dhm, &p, end)) != 0)
    {
        printf("\t[!] mbedtls_dhm_read_params returned %d\n", ret);
        exit(EXIT_FAILURE);
    }
    n = mbedtls_dhm_get_len(&dhm);
    if (n < 64 || n > 512)
    {
        printf("\t[!] Invalid DHM modulus size\n");
        exit(EXIT_FAILURE);
    }

    //
    // Check if signature matches SHA-256 hash of (P, G, Ys)
    //
    printf("[*] Verifying server's RSA signature\n");
    if ((n = (size_t) (end-p-2)) != rsa.MBEDTLS_PRIVATE(len))
    {
        printf("\t[!] Invalid RSA signature size\n");
        exit(EXIT_FAILURE);
    }
    if ((ret = mbedtls_sha1(buf, (int)(p-buf), hash)) != 0)
    {
        printf("\t[!] mbedtls_sha1 returned %d\n", ret);
        exit(EXIT_FAILURE);
    }
    if ((ret = mbedtls_rsa_pkcs1_verify(
        &rsa,
        MBEDTLS_MD_SHA1, 20, hash,
        p+2)) != 0)
    {
        printf("\t[!] mbedtls_rsa_pkcs1_verify returned %d\n", ret);
        exit(EXIT_FAILURE);
    }

    //
    // Send our public value: Yc = G ^ Xc mod P
    //
    printf("[*] Sending public value to server\n");
    n = mbedtls_dhm_get_len(&dhm);
    if ((ret = mbedtls_dhm_make_public(
        &dhm, (int) n,
        buf, n,
        mbedtls_ctr_drbg_random, &ctr_drbg)) != 0)
    {
        printf("\t[!] mbedtls_dhm_make_public returned %d\n", ret);
        exit(EXIT_FAILURE);
    }
    if ((ret = net_sendn(server_fd, buf, n)) != n)
    {
        printf("\t[!] net_sendn returned %d\n", ret);
        exit(EXIT_FAILURE);
    }

    //
    // Derive the shared secret: K = Ys ^ Xc mod P
    //
    printf("[*] Shared secret: ");
    if ((ret = mbedtls_dhm_calc_secret(
        &dhm,
        buf, sizeof(buf), (size_t*) &n,
        mbedtls_ctr_drbg_random, &ctr_drbg)) != 0)
    {
        printf("\n\t[!] mbedtls_dhm_calc_secret returned %d\n", ret);
        exit(EXIT_FAILURE);
    }
    for (int i=0; i<16; i++)
        printf("%02x", buf[i]);
    printf("\n");

    //
    // Receive message using shared secret
    //
    printf("[*] Receiving and decrypting the ciphertext\n");
    mbedtls_aes_setkey_dec(&aes, buf, 256);
    if ((ret = net_recvn(server_fd, buf, 16)) != 16)
    {
        printf("\t[!] net_recvn returned %d\n", ret);
        exit(EXIT_FAILURE);
    }
    mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_DECRYPT, buf, buf);
    buf[16] = '\0';
    printf("\t[+] Text: %s\n", (char*) buf);
}
int main( void )
{
    init();

    int fd = net_tcp_connect(DEFAULT_ADDR, DEFAULT_PORT);
    if (fd != -1)
        peer_handler(fd);
    else
        printf("Can not connect to authenticator!\n");
    close(fd);
}
