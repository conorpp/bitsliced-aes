#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include <openssl/bn.h>
#include <openssl/err.h>

#include "app.h"
#include "../bs.h"
#include "../aes.h"

static void openssl_die(void)
{
    fprintf(stderr,"error: %s\n",
            ERR_error_string(ERR_get_error(),NULL) );
    exit(2);
}

static unsigned int hex2bin(unsigned char ** bin, const char * hex)
{
    int len;
    BIGNUM * bn = NULL;
    if(BN_hex2bn(&bn, (char*)hex) == 0)
    {   openssl_die();    }

    len = BN_num_bytes(bn);
    *bin = (unsigned char *)malloc(len);

    if(BN_bn2bin(bn, *bin) == 0)
    {   openssl_die();  }
    return len;
}


int cli_app(int argc, char * argv[])
{
    uint8_t key[16];
    uint8_t iv[16];
    
    uint8_t * key_p = NULL, * iv_p = NULL;

    int keylen, ivlen;

    if (argc != 5)
    {
        fprintf(stderr, 
                "Bitsliced AES-CTR\n"
                "usage: %s <key-hex> <iv-hex> <input-file> <output-file>\n", argv[0]);
        exit(1);
    }

    char * key_s = argv[1];
    char * iv_s = argv[2];
    char * input_name = argv[3];
    char * output_name = argv[4];

    FILE * input = fopen(input_name, "r");
    if (input == NULL)
    {
        perror("fopen");
        exit(2);
    }

    FILE * output = fopen(output_name, "w+");
    if (output == NULL)
    {
        perror("fopen");
        exit(2);
    }


    ERR_load_crypto_strings();

    keylen = hex2bin(&key_p,key_s);
    if (keylen > 16)
    {
        free(key_p);
        fprintf(stderr,"key must be 16 bytes or less\n");
        exit(2);
    }

    ivlen = hex2bin(&iv_p,iv_s);
    if (ivlen > 16)
    {
        free(iv_p);
        free(key_p);
        fprintf(stderr,"iv must be 16 bytes or less\n");
        exit(2);
    }

    memset(iv,0,16);
    memset(key,0,16);

    memmove(iv, iv_p, ivlen);
    memmove(key, key_p, keylen);

    free(iv_p);
    free(key_p);

    fseek(input, 0L, SEEK_END);
    size_t amt = ftell(input);
    fseek(input, 0L, SEEK_SET);

    uint8_t * pt = (uint8_t *) malloc(amt);
    uint8_t * ct = (uint8_t *) malloc(amt);

    int ptlen = fread(pt, 1, amt, input);
    if (ptlen != amt)
    {
        perror("fread");
        exit(2);
    }

    struct timespec tstart,tend;
    clock_gettime(CLOCK_MONOTONIC, &tstart);
    {
        aes_ctr_encrypt(ct, pt, amt, key, iv);
    }
    clock_gettime(CLOCK_MONOTONIC, &tend);

    double total = (((double)tend.tv_sec + 1.0e-9 * (double)tend.tv_nsec) -
                ((double)tstart.tv_sec + 1.0e-9 * (double)tstart.tv_nsec));

    printf("performance for %d word length\n", WORD_SIZE);
    printf("-------------------------------\n");
    printf("%.5f s\n", total);
    printf("%.15f s/byte\n", total/amt);
    printf("%.5f cycles/byte (for 4 GHz)\n", 4000ull * (1ull<<20) * total/amt);


    if (write(fileno(output), ct, amt) == -1)
    {
        perror("write");
        exit(2);
    }

    free(ct);
    free(pt);

    return 0;
}
