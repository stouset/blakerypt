#include <string.h>
#include <stdio.h>

#include "blakerypt.h"

int main(void) {
    /* the output hash */
    uint8_t       hash[BLAKERYPT_OUT_BYTES];

    /* the input to the sequentially memory-hard function; in the case
     * of password-hashing, a once-hashed password */
    uint8_t const in[BLAKERYPT_BLOCK_BYTES] = { 0 };

    /* a secret "session key" to determine the order in which the
     * iterated hashing accesses the ROM; in the case of password
     * hashing, should be something like MAC(secret_key, password) */
    uint8_t const key[BLAKERYPT_KEY_BYTES]  = { 0 };

    /* memory used is O(2^f_space), time used is O(2^f_time *
     * 2^f_space) */
    int const ret = blakerypt_core(
        hash, in, key, &(blakerypt_param){
        .mode          = BLAKERYPT_MODE_HASH_PASSWORD,
        .f_time        = 0x01,
        .f_space       = 0x1a
    });

    for (int i = 0; i < BLAKERYPT_OUT_BYTES; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");

    return ret;
}
