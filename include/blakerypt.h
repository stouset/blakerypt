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

enum blakerypt_constant {
    BLAKERYPT_BLOCK_BYTES    = BLAKE2B_OUTBYTES,
    BLAKERYPT_OUT_BYTES      = BLAKE2B_OUTBYTES,
    BLAKERYPT_KEY_BYTES      = BLAKE2B_KEYBYTES,
    BLAKERYPT_SALT_BYTES     = BLAKE2B_SALTBYTES,
    BLAKERYPT_PERSONAL_BYTES = BLAKE2B_PERSONALBYTES
};

enum blakerypt_mode {
    BLAKERYPT_MODE_HASH_PASSWORD = 0x00,
    BLAKERYPT_MODE_DERIVE_KEY    = 0x01
};

typedef struct __blakerypt_param {
    enum blakerypt_mode mode;
    uint8_t             f_time;
    uint8_t             f_space;
    uint32_t            key_id;
    uint8_t             personal[BLAKERYPT_PERSONAL_BYTES];
} blakerypt_param;

int blakerypt_core(
    uint8_t               out[restrict static BLAKERYPT_OUT_BYTES],
    uint8_t         const in[restrict static BLAKERYPT_BLOCK_BYTES],
    uint8_t         const key[restrict static BLAKERYPT_KEY_BYTES],
    blakerypt_param const * restrict context
);

#pragma GCC visibility pop

/*

enum blakerypt_constant {
    BLAKERYPT_OUT_BYTES      = BLAKE2B_OUTBYTES,
    BLAKERYPT_KEY_BYTES      = BLAKE2B_KEYBYTES,
    BLAKERYPT_SALT_BYTES     = BLAKE2B_SALTBYTES,
    BLAKERYPT_OUTLEN_BYTES   = 1,
    BLAKERYPT_SALTLEN_BYTES  = 1,
    BLAKERYPT_MODE_BYTES     = 1,
    BLAKERYPT_KEYID_BYTES    = 1,
    BLAKERYPT_TIME_BYTES     = 1,
    BLAKERYPT_CONTEXT_BYTES  = BLAKE2B_PERSONALBYTES   -
                               BLAKERYPT_OUTLEN_BYTES  -
                               BLAKERYPT_SALTLEN_BYTES -
                               BLAKERYPT_MODE_BYTES    -
                               BLAKERYPT_KEYID_BYTES   -
                               BLAKERYPT_TIME_BYTES


};

enum blakerypt_mode {
    BLAKERYPT_DERIVE_PASSWORD = 0x00,
    BLAKERYPT_DERIVE_KEY      = 0x01
};

enum blakerypt_personal_offset {
    BLAKERYPT_OUTLEN_OFFSET  = 0,
    BLAKERYPT_SALTLEN_OFFSET = BLAKERYPT_OUTLEN_OFFSET  + BLAKERYPT_OUTLEN_BYTES,
    BLAKERYPT_MODE_OFFSET    = BLAKERYPT_SALTLEN_OFFSET + BLAKERYPT_SALTLEN_BYTES,
    BLAKERYPT_KEYID_OFFSET   = BLAKERYPT_MODE_OFFSET    + BLAKERYPT_MODE_BYTES,
    BLAKERYPT_TIME_OFFSET    = BLAKERYPT_KEYID_OFFSET   + BLAKERYPT_KEYID_BYTES,
    BLAKERYPT_CONTEXT_OFFSET = BLAKERYPT_TIME_OFFSET    + BLAKERYPT_TIME_BYTES
};

typedef struct __blakerypt_state {
    blake2b_param P[1];
    blake2b_state S[2];
} blakerypt_state;

int blakerypt_core(
          uint8_t  out[BLAKERYPT_OUT_BYTES],
    const uint8_t  key[BLAKERYPT_KEY_BYTES],
    const uint8_t  salt[BLAKERYPT_SALT_BYTES],
    const uint8_t  context[BLAKERYPT_CONTEXT_BYTES],
    const uint8_t  *pass,
    const uint8_t  outlen,
    const uint8_t  keylen,
    const uint8_t  passlen,
    const uint8_t  f_time,
    const uint8_t  f_space,
    const enum blakerypt_mode mode
);
*/
#endif
