/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.] */

#include <openssl/md4.h>

#include <stdlib.h>
#include <string.h>

#include "../../internal.h"


uint8_t *MD4(const uint8_t *data, size_t len, uint8_t *out) {
  MD4_CTX ctx;
  MD4_Init(&ctx);
  MD4_Update(&ctx, data, len);
  MD4_Final(out, &ctx);

  return out;
}

/* Implemented from RFC1186 The MD4 Message-Digest Algorithm. */

int MD4_Init(MD4_CTX *md4) {
  OPENSSL_memset(md4, 0, sizeof(MD4_CTX));
  // md4->h[0] = 0x67452301UL;
  // md4->h[1] = 0xefcdab89UL;
  // md4->h[2] = 0x98badcfeUL;
  // md4->h[3] = 0x10325476UL;
  md4->h[0] = 0x7380166FUL;
  md4->h[1] = 0x4914B2B9UL;
  md4->h[2] = 0x172442D7UL;
  md4->h[3] = 0xDA8A0600UL;
  md4->h[4] = 0xA96F30BCUL;
  md4->h[5] = 0x163138AAUL;
  md4->h[6] = 0xE38DEE4DUL;
  md4->h[7] = 0xB0FB0E4EUL;
  return 1;
}

void md4_block_data_order(uint32_t *state, const uint8_t *data, size_t num);

#define DATA_ORDER_IS_BIG_ENDIAN
// #define DATA_ORDER_IS_LITTLE_ENDIAN

#define HASH_CTX MD4_CTX
#define HASH_CBLOCK 64
#define HASH_UPDATE MD4_Update
#define HASH_TRANSFORM MD4_Transform
#define HASH_FINAL MD4_Final
#define HASH_MAKE_STRING(c, s) \
  do {                         \
    uint32_t ll;               \
    ll = (c)->h[0];            \
    HOST_l2c(ll, (s));         \
    ll = (c)->h[1];            \
    HOST_l2c(ll, (s));         \
    ll = (c)->h[2];            \
    HOST_l2c(ll, (s));         \
    ll = (c)->h[3];            \
    HOST_l2c(ll, (s));         \
    ll = (c)->h[4];            \
    HOST_l2c(ll, (s));         \
    ll = (c)->h[5];            \
    HOST_l2c(ll, (s));         \
    ll = (c)->h[6];            \
    HOST_l2c(ll, (s));         \
    ll = (c)->h[7];            \
    HOST_l2c(ll, (s));         \
  } while (0)
#define HASH_BLOCK_DATA_ORDER md4_block_data_order


#include "../digest/md32_common.h"


#define RSL(A, I)               (((A) << (I)) | ((A) >> (32 - (I))))
#define FF0_15(X, Y, Z)         ((X) ^ (Y) ^ (Z))
#define FF16_63(X, Y, Z)        (((X) & (Y)) | ((X) & (Z)) | ((Y) & (Z)))
#define GG0_15(X, Y, Z)         ((X) ^ (Y) ^ (Z))
#define GG16_63(X, Y, Z)        (((X) & (Y)) | ((~(X)) & (Z)))
#define P0(X)                   ((X) ^ RSL((X), 9) ^ RSL((X), 17))
#define P1(X)                   ((X) ^ RSL((X), 15) ^ RSL((X), 23))

void md4_block_data_order(uint32_t *state, const uint8_t *data, size_t num) 
// static void SM3_block_data_order(SM3_CTX *ctx, const void *in, size_t num)
{
    int j;
    uint32_t W[68], W1[64];
    uint32_t A, B, C, D, E, F, G, H, SS1, SS2, TT1, TT2, T0_15, T16_63;
    const uint8_t *pblock = (const uint8_t *)data;

    while (num--) /*num is the number of SM3 block count*/
    {
        /*Expend message*/
        for (j = 0; j < 16; j++)
        {
            HOST_c2l(pblock, W[j]);
#ifdef SM3DEBUG
            printf("[0x%08x]%c", W[j], ((j + 1) % 4 ? ' ' : '\n'));
#endif
        }
        /*pblock += SM3_CBLOCK;*/
#ifdef SM3DEBUG
        printf("----------------W[]--------------------\n");    
#endif
        for (j = 16; j < 68; j++)
        {
            W[j] = W[j - 16] ^ W[j - 9] ^ RSL(W[j - 3], 15), W[j] = P1(W[j]) ^ RSL(W[j - 13], 7) ^ W[j - 6];
#ifdef SM3DEBUG
            printf("[0x%08x]%c", W[j], ((j + 1) % 4 ? ' ' : '\n'));
#endif
        }
        
#ifdef SM3DEBUG
        printf("-----------------W1[]-------------------\n");    
#endif
        for (j = 0; j < 64; j++)
        {
            W1[j] = W[j] ^ W[j + 4];
#ifdef SM3DEBUG
            printf("[0x%08x]%c", W1[j], ((j + 1) % 4 ? ' ' : '\n'));
#endif
        }

        /*Initialize value*/
        A = state[0], B = state[1], C = state[2], D = state[3];
        E = state[4], F = state[5], G = state[6], H = state[7];
        T0_15 = 0x79CC4519UL, T16_63 = 0x7A879D8AUL;
        for (j = 0; j < 16; j++)
        {
            SS1 = RSL(A, 12) + E + RSL(T0_15, j), SS1 = RSL(SS1, 7);
            SS2 = SS1 ^ RSL(A, 12);
            TT1 = FF0_15(A, B, C) + D + SS2 + W1[j];
            TT2 = GG0_15(E, F, G) + H + SS1 + W[j];
            D = C;
            C = RSL(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = RSL(F, 19);
            F = E;
            E = P0(TT2);
#ifdef SM3DEBUG
            printf("%02d [%08x %08x %08x %08x %08x %08x %08x %08x]\n", j, A, B, C, D, E, F, G, H);
#endif
        }
        for (j = 16; j < 64; j++)
        {
            SS1 = RSL(A, 12) + E + RSL(T16_63, (j % 32)), SS1 = RSL(SS1, 7);
            SS2 = SS1 ^ RSL(A, 12);
            TT1 = FF16_63(A, B, C) + D + SS2 + W1[j];
            TT2 = GG16_63(E, F, G) + H + SS1 + W[j];
            D = C;
            C = RSL(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = RSL(F, 19);
            F = E;
            E = P0(TT2);
#ifdef SM3DEBUG
            printf("%02d [%08x %08x %08x %08x %08x %08x %08x %08x]\n", j, A, B, C, D, E, F, G, H);
#endif
        }
        state[0] ^= A;
        state[1] ^= B;
        state[2] ^= C;
        state[3] ^= D;
        state[4] ^= E;
        state[5] ^= F;
        state[6] ^= G;
        state[7] ^= H;
    }
}

#undef DATA_ORDER_IS_LITTLE_ENDIAN
#undef HASH_CTX
#undef HASH_CBLOCK
#undef HASH_UPDATE
#undef HASH_TRANSFORM
#undef HASH_FINAL
#undef HASH_MAKE_STRING
#undef HASH_BLOCK_DATA_ORDER
#undef RSL
#undef FF0_15 
#undef FF16_63
#undef ROTATE
#undef GG0_15
#undef GG16_63
#undef P0
#undef P1
