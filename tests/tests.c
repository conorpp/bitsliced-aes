#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "../utils.h"
#include "../aes.h"

#ifdef TEST_FOOTPRINT
#define printf(fmt, ...) (0)
#define fprintf(f,fmt, ...) (0)
#else
#include <stdio.h>
#endif

void aes_ecb_test()
{
    uint8_t key_vector[16] = "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c";
    uint8_t pt_vector[16] =  "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a";
    uint8_t ct_vector[16] =  "\x3a\xd7\x7b\xb4\x0d\x7a\x36\x60\xa8\x9e\xca\xf3\x24\x66\xef\x97";
    uint8_t output[16];
    uint8_t input[16];
    
    printf("AES ECB\n");

    aes_ecb_encrypt(output, pt_vector,16,key_vector);


    printf("cipher text: \n");
    dump_hex(output, 16);

    aes_ecb_decrypt(input, output, 16, key_vector);

    printf("plain text: \n");
    dump_hex((uint8_t * )input,16);

    if (memcmp(pt_vector, input, 16) != 0)
    {
        fprintf(stderr,"error: decrypted ciphertext is not the same as the input plaintext\n");
        exit(1);
    }
    else if (memcmp(ct_vector, output, 16) != 0)
    {
        fprintf(stderr,"error: ciphertext is not the same as the test vector\n");
        exit(1);
    }
    else
    {
        printf("ECB passes test vector\n\n");
    }
}

void aes_ctr_test()
{
// Test vector from NIST for 4 input blocks
#define AES_CTR_TESTS_BYTES 64

    uint8_t key_vector[16] =
        "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c";

    uint8_t iv_vector[16]  =
        "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff";

    uint8_t pt_vector[AES_CTR_TESTS_BYTES] =
        "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a"
        "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51"
        "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef"
        "\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10"
        ;

    uint8_t ct_vector[AES_CTR_TESTS_BYTES] =
        "\x87\x4d\x61\x91\xb6\x20\xe3\x26\x1b\xef\x68\x64\x99\x0d\xb6\xce"
        "\x98\x06\xf6\x6b\x79\x70\xfd\xff\x86\x17\x18\x7b\xb9\xff\xfd\xff"
        "\x5a\xe4\xdf\x3e\xdb\xd5\xd3\x5e\x5b\x4f\x09\x02\x0d\xb0\x3e\xab"
        "\x1e\x03\x1d\xda\x2f\xbe\x03\xd1\x79\x21\x70\xa0\xf3\x00\x9c\xee"
        ;

    uint8_t output[AES_CTR_TESTS_BYTES];
    uint8_t input[AES_CTR_TESTS_BYTES];

    printf("AES CTR\n");

    aes_ctr_encrypt(output,pt_vector,AES_CTR_TESTS_BYTES,key_vector, iv_vector);

    printf("cipher text: \n");
    dump_hex(output,AES_CTR_TESTS_BYTES);
    
    aes_ctr_decrypt(input,output,AES_CTR_TESTS_BYTES,key_vector, iv_vector);

    printf("plain text: \n");
    dump_hex(input,AES_CTR_TESTS_BYTES);

    if (memcmp(pt_vector, input, AES_CTR_TESTS_BYTES) != 0)
    {
        fprintf(stderr,"error: decrypted ciphertext is not the same as the input plaintext\n");
        exit(1);
    }
    else if (memcmp(ct_vector, output, AES_CTR_TESTS_BYTES) != 0)
    {
        fprintf(stderr,"error: ciphertext is not the same as the test vector\n");
        exit(1);
    }
    else
    {
        printf("CTR passes test vector\n\n");
    }

}


