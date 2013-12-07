/*
 * blakerypt reference source code package
 *
 * Written in 2013 by Stephen Touset <stephen@touset.org>
 *
 * To the extent possible under law, the author(s) have dedicated all copyright
 * and related and neighboring rights to this software to the public domain
 * worldwide. This software is distributed without any warranty.
 * You should have received a copy of the CC0 Public Domain Dedication along with
 * this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
 */

#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "blakerypt.h"
#include "blake2.h"

/* converts a size factor into a size with exponential growth */
#define BITS_TO_MAX_SIZE(factor) \
    (1 << factor)

/* returns the maximum number of items of the provided size capable of
   being stored in a buffer with the provided size factor */
#define BITS_TO_MAX_COUNT(factor, size) \
    (size_t const)(BITS_TO_MAX_SIZE((factor)) / (size))

typedef struct __blakerypt_rom {
    size_t        blocks;
    uint8_t const (*rom)[BLAKERYPT_BLOCK_BYTES];
} blakerypt_rom;

static inline void blakerypt_zero(
    void * const buffer,
    size_t       bytes
) {
    volatile uint8_t *buffer_p = buffer;

    while(bytes--)
        *buffer_p++ = 0;
}

static inline void blakerypt_block_xor(
    uint8_t       * const restrict out,
    uint8_t const * const restrict in1,
    uint8_t const * const restrict in2,
    size_t  const                  count
) {
    for (size_t i = 0; i < count; ++i) {
        out[i] = in1[i] ^ in2[i];
    }
}

static void blakerypt_block_mix(
    uint8_t       out[const static BLAKERYPT_BLOCK_BYTES],
    uint8_t const in[const static BLAKERYPT_BLOCK_BYTES]
) {
    /* allows us to calculate the index of items in the final shuffled
     * array, so we can insert items into it pre-shuffled and thus
     * avoid memcpy'ing around results after the fact */
    #define SHUFFLE(i) (                    \
        ((i) * BLAKERYPT_BLOCK_COUNT / 2) + \
        ((i) / 2)                           \
    ) % (BLAKERYPT_BLOCK_COUNT)

    /* simplify indexing logic by treating the input and output blocks
     * as arrays of native blake2b output size */
    uint8_t (*in_a)[BLAKE2B_OUTBYTES]  = (uint8_t (*)[BLAKE2B_OUTBYTES]) in;
    uint8_t (*out_a)[BLAKE2B_OUTBYTES] = (uint8_t (*)[BLAKE2B_OUTBYTES]) out;

    /* the last index of the input is originally copied to the output,
       since it is used in the first iteration of the loop */
    memcpy(
        out_a + BLAKERYPT_BLOCK_COUNT - 1,
        in_a  + BLAKERYPT_BLOCK_COUNT - 1,
        BLAKE2B_OUTBYTES
    );

    for (
        size_t i_in = 0, i_out = BLAKERYPT_BLOCK_COUNT - 1, i_out_last = 0;
        i_in < BLAKERYPT_BLOCK_COUNT;
        ++i_in
    ) {
        i_out_last = i_out;
        i_out      = SHUFFLE(i_in);

        blakerypt_block_xor(
            out_a[i_out],
            out_a[i_out_last],
            in_a[i_in],
            BLAKE2B_OUTBYTES
        );

        blake2b(
            out_a[i_out],     out_a[i_out],     NULL,
            BLAKE2B_OUTBYTES, BLAKE2B_OUTBYTES, 0
        );
    }
}

static void blakerypt_rom_init(
    uint8_t (* const restrict rom)[BLAKERYPT_BLOCK_BYTES],
    uint8_t const             in[const restrict static BLAKERYPT_BLOCK_BYTES],
    size_t  const             blocks
) {
    memcpy(rom, in, BLAKERYPT_BLOCK_BYTES);

    for (size_t i = 1; i < blocks; ++i) {
        blakerypt_block_mix(rom[i], rom[i - 1]);
    }
}

static int blakerypt_rom_mix(
    blakerypt_rom   const * const rom,
    uint8_t                       out [const restrict static BLAKERYPT_BLOCK_BYTES],
    uint8_t                 const key [const restrict static BLAKERYPT_KEY_BYTES],
    blakerypt_param const * const context
) {
    size_t const iterations = BITS_TO_MAX_SIZE(context->f_time);

    /* fail if we don't iterate at least once */
    if (iterations == 0)
        goto err;

    /* TODO: define rom_index in terms of endianness */
    uint8_t out_tmp[BLAKERYPT_BLOCK_BYTES];
    size_t  rom_index      = 0;
    uint8_t *rom_index_ptr = (uint8_t *) &rom_index;

    /* fail if we can't lock sensitive data into memory */
    if (
        mlock(out_tmp,    sizeof(out_tmp))   ||
        mlock(&rom_index, sizeof(rom_index))
    ) {
        goto err;
    }

    /* clear the output buffer so it can be used with an initial XOR */
    memset(out, 0, BLAKERYPT_BLOCK_BYTES);

    for(size_t i = 0; i < iterations; ++i) {
        for(size_t j = 0; j < rom->blocks; ++j) {
            /* the number of times this line has been run */
            rom_index = rom->blocks * i + j;

            /* MAC the key and the loop counter to determine which
               ROM index to use */
            blake2b(
                rom_index_ptr,     rom_index_ptr,     key,
                sizeof(rom_index), sizeof(rom_index), BLAKERYPT_KEY_BYTES
            );

            blakerypt_block_xor(
                out_tmp,
                out,
                rom->rom[rom_index % rom->blocks],
                BLAKERYPT_BLOCK_BYTES
            );

            blakerypt_block_mix(out, out_tmp);
        }
    }

    blakerypt_zero(out_tmp,    sizeof(out_tmp));
    blakerypt_zero(&rom_index, sizeof(rom_index));

    return 0;

 err:
    return -1;
}

static blakerypt_rom const * blakerypt_rom_new(
    uint8_t         const in[const restrict static BLAKERYPT_BLOCK_BYTES],
    blakerypt_param const * const context
) {
    size_t const blocks = BITS_TO_MAX_COUNT(
        context->f_space, BLAKERYPT_BLOCK_BYTES
    );

    /* fail if we don't have at least one block in the ROM */
    if (blocks == 0)
        goto err;

    uint8_t (* const rom)[BLAKERYPT_BLOCK_BYTES] = malloc(
        blocks * BLAKERYPT_BLOCK_BYTES
    );

    /* fail if we didn't allocate any ROM */
    if (rom == NULL)
        goto err;

    /* fail if we can't lock the rom's pages into memory */
    if (mlock(rom, blocks * BLAKERYPT_BLOCK_BYTES))
        goto err1;

    blakerypt_rom * const ret = malloc(
        sizeof(blakerypt_rom)
    );

    /* fail if we couldn't allocate the ROM structure to return */
    if (ret == NULL)
        goto err1;

    blakerypt_rom_init(
        rom, in, blocks
    );

    ret->blocks = blocks;
    ret->rom    = rom;

    return ret;

 err1:
    free(rom);

 err:
    return NULL;
}

static void blakerypt_rom_free(
    blakerypt_rom const * const restrict rom
) {
    blakerypt_zero((void *) rom->rom, rom->blocks * BLAKERYPT_BLOCK_BYTES);
    free((void *) rom->rom);
    free((void *) rom);
}

int blakerypt_core(
    uint8_t       out[const restrict static BLAKERYPT_BLOCK_BYTES],
    uint8_t const key[const restrict static BLAKERYPT_KEY_BYTES],
    uint8_t const in[const restrict static BLAKERYPT_BLOCK_BYTES],
    blakerypt_param const * const restrict context
) {
    /* fail if we can't lock the pages for sensitive data into memory */
    if (
        mlock(out, BLAKERYPT_BLOCK_BYTES) ||
        mlock(key, BLAKERYPT_KEY_BYTES)   ||
        mlock(in,  BLAKERYPT_BLOCK_BYTES)
    ) {
        goto err;
    }

    /* fail if we can't represent (2 << f_time) in a size_t */
    if (context->f_time > sizeof(size_t) * 8 - 1)
        goto err;

    /* fail if we can't represent (2 << f_space) in a size_t */
    if (context->f_space > sizeof(size_t) * 8 - 1)
        goto err;

    blakerypt_rom const * const rom = blakerypt_rom_new(
        in, context
    );

    /* fail if the ROM wasn't created */
    if (rom == NULL)
        goto err;

    /* mix the contents of the ROM based on the key */
    if (blakerypt_rom_mix(rom, out, key, context))
        goto err1;

    blakerypt_rom_free(rom);

    return 0;

 err1:
    blakerypt_rom_free(rom);

 err:
    /* ensure the output is zeroed out if we fail, to avoid garbage
     * left in the output */
    memset(out, 0, BLAKERYPT_BLOCK_BYTES);

    return -1;
}

/* compile-time self-testing */

_Static_assert(
    BLAKERYPT_BLOCK_BYTES > 1,
    "block size must be greater than one to avoid rom_index overflow"
);

_Static_assert(
    BLAKERYPT_KEY_BYTES > sizeof(size_t),
    "key size must be at least large enough to hold any array index"
);

_Static_assert(
    BLAKERYPT_BLOCK_BYTES == BLAKERYPT_BLOCK_COUNT * BLAKE2B_OUTBYTES,
    "a block should be the same size as block_count hash outputs"
);
