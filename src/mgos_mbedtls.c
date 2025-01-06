/*
 * Copyright (c) 2014-2018 Cesanta Software Limited
 * All rights reserved
 */

#include <stdbool.h>

#include "mongoose.h"

#include "mbedtls/aes.h"
#include "mbedtls/entropy.h"
#include "mbedtls/md5.h"
#include "mbedtls/sha1.h"
#include "mbedtls/sha256.h"

/* Crypto functions for Mongoose. */
void mg_hash_md5_v(size_t num_msgs, const uint8_t *msgs[],
                   const size_t *msg_lens, uint8_t *digest) {
  size_t i;
  mbedtls_md5_context ctx;
  mbedtls_md5_init(&ctx);
  mbedtls_md5_starts(&ctx);
  for (i = 0; i < num_msgs; i++) {
    mbedtls_md5_update(&ctx, msgs[i], msg_lens[i]);
  }
  mbedtls_md5_finish(&ctx, digest);
  mbedtls_md5_free(&ctx);
}

void mg_hash_sha1_v(size_t num_msgs, const uint8_t *msgs[],
                    const size_t *msg_lens, uint8_t *digest) {
  size_t i;
  mbedtls_sha1_context ctx;
  mbedtls_sha1_init(&ctx);
  mbedtls_sha1_starts(&ctx);
  for (i = 0; i < num_msgs; i++) {
    mbedtls_sha1_update(&ctx, msgs[i], msg_lens[i]);
  }
  mbedtls_sha1_finish(&ctx, digest);
  mbedtls_sha1_free(&ctx);
}

void mg_hash_sha256_v(size_t num_msgs, const uint8_t *msgs[],
                      const size_t *msg_lens, uint8_t *digest) {
  size_t i;
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts(&ctx, false /* is224 */);
  for (i = 0; i < num_msgs; i++) {
    mbedtls_sha256_update(&ctx, msgs[i], msg_lens[i]);
  }
  mbedtls_sha256_finish(&ctx, digest);
  mbedtls_sha256_free(&ctx);
}

/* This function is provided by platforms */
extern int mg_ssl_if_mbed_random(void *ctx, unsigned char *buf, size_t len);

bool mgos_mbedtls_init(void) {
  return true;
}

int mbedtls_sha1_starts_ret(mbedtls_sha1_context *ctx) {
  return mbedtls_sha1_starts(ctx);
}

void mbedtls_sha1_update_ret(mbedtls_sha1_context *ctx,
                             const unsigned char *input, size_t ilen) {
  mbedtls_sha1_update(ctx, input, ilen);
}

void mbedtls_sha1_finish_ret(mbedtls_sha1_context *ctx,
                             unsigned char output[20]) {
  mbedtls_sha1_finish(ctx, output);
}

void mbedtls_sha256_starts_ret(mbedtls_sha256_context *ctx, int is224) {
  mbedtls_sha256_starts(ctx, is224);
}

void mbedtls_sha256_update_ret(mbedtls_sha256_context *ctx,
                               const unsigned char *input, size_t ilen) {
  mbedtls_sha256_update(ctx, input, ilen);
}

void mbedtls_sha256_finish_ret(mbedtls_sha256_context *ctx,
                               unsigned char output[32]) {
  mbedtls_sha256_finish(ctx, output);
}

// this is normally done by esp-idf framework via MACRO, however as we do not
// have sources, we have to do it ourselves? :/ another way would be to tell the
// compiler this but so far we do not know how.

// compatibility for ota-common
#undef mbedtls_aes_init
#undef mbedtls_aes_free
#undef mbedtls_aes_setkey_enc
#undef mbedtls_aes_setkey_dec
#undef mbedtls_aes_crypt_ecb

void mbedtls_aes_init(mbedtls_aes_context *ctx) {
  esp_aes_init(ctx);
}

void mbedtls_aes_free(mbedtls_aes_context *ctx) {
  esp_aes_free(ctx);
}

int mbedtls_aes_setkey_dec(mbedtls_aes_context *ctx, const unsigned char *key,
                           unsigned int keybits)

{
  return esp_aes_setkey(ctx, key, keybits);
}

int mbedtls_aes_setkey_enc(mbedtls_aes_context *ctx, const unsigned char *key,
                           unsigned int keybits)

{
  return esp_aes_setkey(ctx, key, keybits);
}

int mbedtls_aes_crypt_ecb(mbedtls_aes_context *ctx, int mode,
                          const unsigned char input[16],
                          unsigned char output[16]) {
  return esp_aes_crypt_ecb(ctx, mode, input, output);
}
