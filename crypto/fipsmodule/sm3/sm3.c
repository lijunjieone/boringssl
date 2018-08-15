/* crypto/sm3/sm3.c */
/*
 * Written by caichenghang for the TaSSL project.
 */
/* ====================================================================
 * Copyright (c) 2016 - 2018 Beijing JN TASS Technology Co.,Ltd.  All 
 * rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by Beijing JN TASS 
 *    Technology Co.,Ltd. TaSSL Project.(http://www.tass.com.cn/)"
 *
 * 4. The name "TaSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    TaSSL@tass.com.cn.
 *
 * 5. Products derived from this software may not be called "TaSSL"
 *    nor may "TaSSL" appear in their names without prior written
 *    permission of the TaSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Beijing JN TASS 
 *    Technology Co.,Ltd. TaSSL Project.(http://www.tass.com.cn/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE TASSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE TASSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes software developed by the TaSSL Project
 * for use in the OpenSSL Toolkit (http://www.openssl.org/).
 *
 */

#include <openssl/sm3.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "../../internal.h"
#include <openssl/sm3.h>

#include <stdlib.h>
#include <string.h>

#include "../../internal.h"


uint8_t *SM3(const uint8_t *data, size_t len, uint8_t *out) {
  SM3_CTX ctx;
  SM3_Init(&ctx);
  SM3_Update(&ctx, data, len);
  SM3_Final(out, &ctx);

  return out;
}

/* Implemented from RFC1186 The SM3 Message-Digest Algorithm. */

int SM3_Init(SM3_CTX *sm3) {
  OPENSSL_memset(sm3, 0, sizeof(SM3_CTX));
  // sm3->h[0] = 0x67452301UL;
  // sm3->h[1] = 0xefcdab89UL;
  // sm3->h[2] = 0x98badcfeUL;
  // sm3->h[3] = 0x10325476UL;
  sm3->h[0] = 0x7380166FUL;
  sm3->h[1] = 0x4914B2B9UL;
  sm3->h[2] = 0x172442D7UL;
  sm3->h[3] = 0xDA8A0600UL;
  sm3->h[4] = 0xA96F30BCUL;
  sm3->h[5] = 0x163138AAUL;
  sm3->h[6] = 0xE38DEE4DUL;
  sm3->h[7] = 0xB0FB0E4EUL;
  return 1;
}

void SM3_block_data_order(uint32_t *state, const uint8_t *data, size_t num);

#define DATA_ORDER_IS_BIG_ENDIAN
// #define DATA_ORDER_IS_LITTLE_ENDIAN

#define HASH_CTX SM3_CTX
#define HASH_CBLOCK 64
#define HASH_UPDATE SM3_Update
#define HASH_TRANSFORM SM3_Transform
#define HASH_FINAL SM3_Final
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
#define HASH_BLOCK_DATA_ORDER SM3_block_data_order


#include "../digest/md32_common.h"


#define RSL(A, I)               (((A) << (I)) | ((A) >> (32 - (I))))
#define FF0_15(X, Y, Z)         ((X) ^ (Y) ^ (Z))
#define FF16_63(X, Y, Z)        (((X) & (Y)) | ((X) & (Z)) | ((Y) & (Z)))
#define GG0_15(X, Y, Z)         ((X) ^ (Y) ^ (Z))
#define GG16_63(X, Y, Z)        (((X) & (Y)) | ((~(X)) & (Z)))
#define P0(X)                   ((X) ^ RSL((X), 9) ^ RSL((X), 17))
#define P1(X)                   ((X) ^ RSL((X), 15) ^ RSL((X), 23))

void SM3_block_data_order(uint32_t *state, const uint8_t *data, size_t num) 
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
