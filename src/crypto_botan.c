/*
** SQLCipher
** http://sqlcipher.net
**
** Copyright (c) 2008 - 2013, ZETETIC LLC
** All rights reserved.
**
** Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions are met:
**     * Redistributions of source code must retain the above copyright
**       notice, this list of conditions and the following disclaimer.
**     * Redistributions in binary form must reproduce the above copyright
**       notice, this list of conditions and the following disclaimer in the
**       documentation and/or other materials provided with the distribution.
**     * Neither the name of the ZETETIC LLC nor the
**       names of its contributors may be used to endorse or promote products
**       derived from this software without specific prior written permission.
**
** THIS SOFTWARE IS PROVIDED BY ZETETIC LLC ''AS IS'' AND ANY
** EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
** WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
** DISCLAIMED. IN NO EVENT SHALL ZETETIC LLC BE LIABLE FOR ANY
** DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
** (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
** LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
** ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
** (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
** SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
**
*/
/* BEGIN SQLCIPHER */

// TODO REMOVE
//#define SQLITE_HAS_CODEC
//#define SQLCIPHER_CRYPTO_BOTAN
// END TODO REMOVE

#ifdef SQLITE_HAS_CODEC
#ifdef SQLCIPHER_CRYPTO_BOTAN
#include "crypto.h"
#include "sqlcipher.h"
#include <botan/ffi.h>

static botan_rng_t bt_rng;
static char* bt_rng_name = "user-threadsafe";
static unsigned int bt_init_count = 0;

int sqlcipher_botan_setup(sqlcipher_provider *p);

static int sqlcipher_botan_activate(void *ctx) {
  CODEC_TRACE_MUTEX("sqlcipher_botan_activate: entering SQLCIPHER_MUTEX_PROVIDER_ACTIVATE\n");
  sqlite3_mutex_enter(sqlcipher_mutex(SQLCIPHER_MUTEX_PROVIDER_ACTIVATE));
  CODEC_TRACE_MUTEX("sqlcipher_botan_activate: entered SQLCIPHER_MUTEX_PROVIDER_ACTIVATE\n");
  if (bt_init_count == 0) {
    if (botan_rng_init(&bt_rng, bt_rng_name) != BOTAN_FFI_SUCCESS) {
      return SQLITE_ERROR;
    }
  }
  bt_init_count++;

  CODEC_TRACE_MUTEX("sqlcipher_botan_activate: leaving SQLCIPHER_MUTEX_PROVIDER_ACTIVATE\n");
  sqlite3_mutex_leave(sqlcipher_mutex(SQLCIPHER_MUTEX_PROVIDER_ACTIVATE));
  CODEC_TRACE_MUTEX("sqlcipher_botan_activate: left SQLCIPHER_MUTEX_PROVIDER_ACTIVATE\n");
  return SQLITE_OK;
}

static int sqlcipher_botan_deactivate(void *ctx) {
  CODEC_TRACE_MUTEX("sqlcipher_botan_deactivate: entering SQLCIPHER_MUTEX_PROVIDER_ACTIVATE\n");
  sqlite3_mutex_enter(sqlcipher_mutex(SQLCIPHER_MUTEX_PROVIDER_ACTIVATE));
  CODEC_TRACE_MUTEX("sqlcipher_botan_deactivate: entered SQLCIPHER_MUTEX_PROVIDER_ACTIVATE\n");

  bt_init_count--;
  if (bt_init_count == 0) {
    botan_rng_destroy(bt_rng);
  }

  CODEC_TRACE_MUTEX("sqlcipher_botan_deactivate: leaving SQLCIPHER_MUTEX_PROVIDER_ACTIVATE\n");
  sqlite3_mutex_leave(sqlcipher_mutex(SQLCIPHER_MUTEX_PROVIDER_ACTIVATE));
  CODEC_TRACE_MUTEX("sqlcipher_botan_deactivate: left SQLCIPHER_MUTEX_PROVIDER_ACTIVATE\n");
  return SQLITE_OK;
}

static int sqlcipher_botan_add_random(void *ctx, void *buffer, int length) {
  return SQLITE_OK;
}

/* generate a defined number of random bytes */
static int sqlcipher_botan_random (void *ctx, void *buffer, int length) {
  int rc = SQLITE_OK;
  CODEC_TRACE_MUTEX("sqlcipher_botan_random: entering SQLCIPHER_MUTEX_PROVIDER_RAND\n");
  sqlite3_mutex_enter(sqlcipher_mutex(SQLCIPHER_MUTEX_PROVIDER_RAND));
  CODEC_TRACE_MUTEX("sqlcipher_botan_random: entered SQLCIPHER_MUTEX_PROVIDER_RAND\n");

  if (botan_rng_get(bt_rng, (uint8_t*)buffer, length) != BOTAN_FFI_SUCCESS) {
    rc = SQLITE_ERROR;
  }

  CODEC_TRACE_MUTEX("sqlcipher_botan_random: leaving SQLCIPHER_MUTEX_PROVIDER_RAND\n");
  sqlite3_mutex_leave(sqlcipher_mutex(SQLCIPHER_MUTEX_PROVIDER_RAND));
  CODEC_TRACE_MUTEX("sqlcipher_botan_random: left SQLCIPHER_MUTEX_PROVIDER_RAND\n");

  return rc;
}

static const char* sqlcipher_botan_get_provider_name(void *ctx) {
  return "botan";
}

static const char* sqlcipher_botan_get_provider_version(void *ctx) {
  return botan_version_string();
}

// TODO add context-awareness below
static const char* sqlcipher_botan_get_cipher(void *ctx) {
  return "aes-256-cbc";
}

static int sqlcipher_botan_get_key_sz(void *ctx) {
  return 32;
}

static int sqlcipher_botan_get_iv_sz(void *ctx) {
  return 16;
}

static int sqlcipher_botan_get_block_sz(void *ctx) {
  return 16;
}

static int sqlcipher_botan_get_hmac_sz(void *ctx, int algorithm) {
  switch(algorithm) {
    case SQLCIPHER_HMAC_SHA1:
      return 20;
      break;
    case SQLCIPHER_HMAC_SHA256:
      return 32;
      break;
    case SQLCIPHER_HMAC_SHA512:
      return 64;
      break;
    default:
      return 0;
  }
}

static int sqlcipher_botan_hmac(void *ctx, int algorithm, unsigned char *hmac_key, int key_sz, unsigned char *in, int in_sz, unsigned char *in2, int in2_sz, unsigned char *out) {
  if(in == NULL) goto error;
  int rc = SQLITE_OK;
  botan_mac_t bt_mac;
  char* mac_name = NULL;
  switch(algorithm) {
    case SQLCIPHER_HMAC_SHA1:
      mac_name = "HMAC(SHA-1)";
      break;
    case SQLCIPHER_HMAC_SHA256:
      mac_name = "HMAC(SHA-256)";
      break;
    case SQLCIPHER_HMAC_SHA512:
      mac_name = "HMAC(SHA-512)";
      break;
    default:
      goto error;
  }

  if (botan_mac_init(&bt_mac, mac_name, 0) != BOTAN_FFI_SUCCESS) goto error;
  if (botan_mac_set_key(bt_mac, (const uint8_t*)hmac_key, key_sz) != BOTAN_FFI_SUCCESS) goto error;
  if (botan_mac_update(bt_mac, (const uint8_t*)in, in_sz) != BOTAN_FFI_SUCCESS) goto error;
  if (in2 != NULL) {
    if (botan_mac_update(bt_mac, (const uint8_t*)in2, in2_sz) != BOTAN_FFI_SUCCESS) goto error;
  }
  if (botan_mac_final(bt_mac, out) != BOTAN_FFI_SUCCESS) goto error;

  goto cleanup;
  error:
    rc = SQLITE_ERROR;
  cleanup:
    botan_mac_destroy(bt_mac);
    return rc;
}

static int sqlcipher_botan_kdf(void *ctx, int algorithm, const unsigned char *pass, int pass_sz, unsigned char* salt, int salt_sz, int workfactor, int key_sz, unsigned char *key) {
  int rc = SQLITE_OK; 

  switch(algorithm) {
    case SQLCIPHER_HMAC_SHA1:
      if(botan_pwdhash("PBKDF2(SHA-1)", workfactor, 0, 0, key, key_sz, (const char*)pass, pass_sz, salt, salt_sz) != BOTAN_FFI_SUCCESS) goto error;
      break;
    case SQLCIPHER_HMAC_SHA256:
      if(botan_pwdhash("PBKDF2(SHA-256)", workfactor, 0, 0, key, key_sz, (const char*)pass, pass_sz, salt, salt_sz) != BOTAN_FFI_SUCCESS) goto error;
      break;
    case SQLCIPHER_HMAC_SHA512:
      if(botan_pwdhash("PBKDF2(SHA-512)", workfactor, 0, 0, key, key_sz, (const char*)pass, pass_sz, salt, salt_sz) != BOTAN_FFI_SUCCESS) goto error;
      break;
    default:
      return SQLITE_ERROR;
  }

  goto cleanup;
error:
  rc = SQLITE_ERROR;
cleanup:
  return rc;
}

// TODO port below

static int sqlcipher_botan_cipher(void *ctx, int mode, unsigned char *key, int key_sz, unsigned char *iv, unsigned char *in, int in_sz, unsigned char *out) {
  int rc = SQLITE_OK;
  botan_block_cipher_t bt_cipher;
  if (botan_block_cipher_init(&bt_cipher, "AES-256/CBC") != BOTAN_FFI_SUCCESS) goto error;
  if (botan_block_cipher_set_key(bt_cipher, key, key_sz) != BOTAN_FFI_SUCCESS) goto error;
  if (mode) {
    if(botan_block_cipher_encrypt_blocks(bt_cipher, in, out, in_sz/botan_block_cipher_block_size(bt_cipher)) != BOTAN_FFI_SUCCESS) goto error;
  } else {
    if(botan_block_cipher_decrypt_blocks(bt_cipher, in, out, in_sz/botan_block_cipher_block_size(bt_cipher)) != BOTAN_FFI_SUCCESS) goto error;
  }

  goto cleanup;
error:
  rc = SQLITE_ERROR;
cleanup:
  return rc;
}

static int sqlcipher_botan_ctx_init(void **ctx) {
  sqlcipher_botan_activate(NULL);
  return SQLITE_OK;
}

static int sqlcipher_botan_ctx_free(void **ctx) {
  sqlcipher_botan_deactivate(NULL);
  return SQLITE_OK;
}

static int sqlcipher_botan_fips_status(void *ctx) {
  return 0;
}

int sqlcipher_botan_setup(sqlcipher_provider *p) {
  p->activate = sqlcipher_botan_activate;
  p->deactivate = sqlcipher_botan_deactivate;
  p->random = sqlcipher_botan_random;
  p->get_provider_name = sqlcipher_botan_get_provider_name;
  p->hmac = sqlcipher_botan_hmac;
  p->kdf = sqlcipher_botan_kdf;
  p->cipher = sqlcipher_botan_cipher;
  p->get_cipher = sqlcipher_botan_get_cipher;
  p->get_key_sz = sqlcipher_botan_get_key_sz;
  p->get_iv_sz = sqlcipher_botan_get_iv_sz;
  p->get_block_sz = sqlcipher_botan_get_block_sz;
  p->get_hmac_sz = sqlcipher_botan_get_hmac_sz;
  p->ctx_init = sqlcipher_botan_ctx_init;
  p->ctx_free = sqlcipher_botan_ctx_free;
  p->add_random = sqlcipher_botan_add_random;
  p->fips_status = sqlcipher_botan_fips_status;
  p->get_provider_version = sqlcipher_botan_get_provider_version;
  return SQLITE_OK;
}

#endif
#endif
/* END SQLCIPHER */
