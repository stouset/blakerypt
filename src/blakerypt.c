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

#include "blakerypt.h"
#include "blake2.h"

/* returns the maximum size that can be stored in a given number of
 * bits; left-shifting and subtracting one can overflow, so we start
 * with the maximum size and downshift by an appropriate amount */
#define BITS_TO_MAX_SIZE(bits) \
    (size_t const)(SIZE_MAX >> (sizeof(size_t) * 8 - (bits)))

/* returns the maximum number of items of the given size that can be
 * stored in a buffer whose size is the maximum size storable in the
 * given number of bits; this is probably one fewer than you suspect,
 * for instance, the maximum size storable in 4 bits is 15, and a
 * buffer 15 bits large can only store 3 4-byte items */
#define BITS_TO_MAX_COUNT(bits, size) \
    (size_t const)(BITS_TO_MAX_SIZE((bits)) / (size))

typedef struct __blakerypt_rom {
    size_t        blocks;
    uint8_t const *rom;
} blakerypt_rom;

#pragma pack(push, 1)
/* TODO: endianness of key_id */
typedef struct __blakerypt_salt {
    union {
        struct {
            uint8_t  mode;          //  1
            uint8_t  f_time;        //  2
            uint8_t  f_space;       //  3
            uint8_t  reserved1_;    //  4
            uint32_t key_id;        //  8
            uint64_t reserved2_;    // 16
        };

        uint8_t const salt[BLAKERYPT_SALT_BYTES];
    };
} blakerypt_salt;
#pragma pack(pop)

static void blakerypt_rom_init(
    uint8_t * const restrict rom,
    uint8_t   const          in[const restrict static BLAKERYPT_BLOCK_BYTES],
    size_t    const          blocks
) {
    size_t  const block_size = BLAKERYPT_BLOCK_BYTES;
    size_t  const size       = blocks * block_size;

    memcpy(rom, in, BLAKERYPT_BLOCK_BYTES);

    for (size_t i = block_size; i < size; i += block_size) {
        blake2b(
            rom + i,    rom + i - block_size, NULL,
            block_size, block_size,           0
        );
    }
}

static int blakerypt_rom_mix(
    blakerypt_rom   const * const rom,
    uint8_t                       out [const restrict static BLAKERYPT_OUT_BYTES],
    uint8_t                 const key [const restrict static BLAKERYPT_KEY_BYTES],
    blakerypt_param const * const context
) {
    size_t const iterations = BITS_TO_MAX_SIZE(context->f_time);

    /* fail if we don't iterate at least once */
    if (iterations == 0)
        goto err;

    uint8_t rom_index_hash[BLAKERYPT_KEY_BYTES];
    size_t  rom_index;

    memcpy(rom_index_hash, key, BLAKERYPT_KEY_BYTES);

    blakerypt_salt const salt = {
        .mode          = context->mode,
        .f_time        = context->f_time,
        .f_space       = context->f_space,
        .key_id        = context->key_id,
    };

    blake2b_state S;
    blake2b_param P = {
        .digest_length = BLAKERYPT_OUT_BYTES,
        .fanout        = 1,
        .depth         = 1,
        .salt          = { 0 },
        .personal      = { 0 }
    };

    memcpy(P.salt,     salt.salt,         BLAKERYPT_SALT_BYTES);
    memcpy(P.personal, context->personal, BLAKERYPT_PERSONAL_BYTES);

    blake2b_init_param(&S, &P);

    for(size_t j = 0; j < iterations; ++j) {
        for(size_t k = 0; k < rom->blocks; ++k) {
            blake2b(
                rom_index_hash, rom_index_hash, NULL,
                sizeof(size_t), sizeof(size_t), 0
            );

            /* TODO: explicitly define this in terms of endianness */

            /* mod by rom->blocks + 1 so rom->blocks is a power of 2;
             * this is guaranteed not to overflow if
             * BLAKERYPT_BLOCK_SIZE is greater than 1 */
            rom_index =
                *((size_t *)rom_index_hash) %
                (rom->blocks + 1);

            blake2b_update(
                &S,
                rom->rom + (rom_index * BLAKERYPT_BLOCK_BYTES),
                BLAKERYPT_BLOCK_BYTES
            );
        }
    }

    blake2b_final(&S, out, BLAKERYPT_OUT_BYTES);

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

    uint8_t * const rom = malloc(
        blocks * BLAKERYPT_BLOCK_BYTES
    );

    /* fail if we didn't allocate any ROM */
    if (rom == NULL)
        goto err;

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
    blakerypt_rom const * const rom
) {
    free((void *) rom->rom);
    free((void *) rom);
}

int blakerypt_core(
    uint8_t       out[const restrict static BLAKERYPT_OUT_BYTES],
    uint8_t const in[const restrict static BLAKERYPT_BLOCK_BYTES],
    uint8_t const key[const restrict static BLAKERYPT_KEY_BYTES],
    blakerypt_param const * const restrict context
) {
    /* fail if f_time doesn't have us looping at least once */
    if (context->f_time == 0)
        goto err;

    /* fail if we can't represent (2 << f_time - 1) in a size_t */
    if (context->f_time > sizeof(size_t) * 8)
        goto err;

    /* fail if we can't represent (2 << f_space - 1) in a size_t */
    if (context->f_space > sizeof(size_t) * 8)
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
    memset(out, 0, BLAKERYPT_OUT_BYTES);

    return -1;
}

/* compile-time self-testing */

_Static_assert(
    sizeof(blakerypt_salt) == BLAKE2B_SALTBYTES,
    "the blakerypt_salt struct must be the same size as a BLAKE2B salt"
);

_Static_assert(
    sizeof(size_t) <= sizeof(uint64_t),
    "size_t's must be storable inside a uint64_t for counting threads"
);

_Static_assert(
    BLAKERYPT_BLOCK_BYTES > 1,
    "block size must be greater than one to avoid rom_index overflow"
);
