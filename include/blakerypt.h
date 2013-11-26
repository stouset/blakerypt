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

#ifndef __BLAKERYPT_H__
#define __BLAKERYPT_H__

#include "blake2.h"

#pragma GCC visibility push(default)

#define BLAKERYPT_BLOCK_FACTOR 8
#define BLAKERYPT_BLOCK_COUNT  (2 * BLAKERYPT_BLOCK_FACTOR)

enum blakerypt_sizes {
    BLAKERYPT_BLOCK_BYTES    = BLAKE2B_OUTBYTES * BLAKERYPT_BLOCK_COUNT,
    BLAKERYPT_OUT_BYTES      = BLAKE2B_OUTBYTES,
    BLAKERYPT_KEY_BYTES      = BLAKE2B_OUTBYTES,
    BLAKERYPT_SALT_BYTES     = BLAKE2B_SALTBYTES,
    BLAKERYPT_PERSONAL_BYTES = BLAKE2B_PERSONALBYTES
};

enum blakerypt_modes {
    BLAKERYPT_MODE_HASH_PASSWORD = 0x00,
    BLAKERYPT_MODE_DERIVE_KEY    = 0x01
};

typedef struct __blakerypt_param {
    enum blakerypt_modes mode;
    uint8_t              f_time;
    uint8_t              f_space;
    uint32_t             key_id;
    uint8_t              personal[BLAKERYPT_PERSONAL_BYTES];
} blakerypt_param;

int blakerypt_core(
    uint8_t               out[restrict static BLAKERYPT_BLOCK_BYTES],
    uint8_t         const key[restrict static BLAKERYPT_BLOCK_BYTES],
    uint8_t         const in[restrict static BLAKERYPT_BLOCK_BYTES],
    blakerypt_param const * restrict context
);

#pragma GCC visibility pop

#endif
