// Copyright (c) 2011-present, Facebook, Inc.  All rights reserved.
//  This source code is licensed under both the GPLv2 (found in the
//  COPYING file in the root directory) and Apache 2.0 License
//  (found in the LICENSE.Apache file in the root directory).
//
// Copyright (c) 2011 The LevelDB Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file. See the AUTHORS file for names of contributors.
//

#pragma once

#ifdef OPENSSL
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#endif

namespace rocksdb {
inline bool InitCrypto() {
  return true;
}

// Copied from MySQL

/**
  Transforms an arbitrary long key into a fixed length AES key

  AES keys are of fixed length. This routine takes an arbitrary long key
  iterates over it in AES key length increment and XORs the bytes with the
  AES key buffer being prepared.
  The bytes from the last incomplete iteration are XORed to the start
  of the key until their depletion.
  Needed since crypto function routines expect a fixed length key.

  @param key        [in]       Key to use for real key creation
  @param key_length [in]       Length of the key
  @param rkey       [out]      Real key (used by OpenSSL/YaSSL)
  @param opmode     [out]      encryption mode
*/

// void AesCreateKey(const unsigned char *key, size_t key_length,
//                   unsigned char *rkey)
// {
//   const unsigned int key_size = 32;
//   unsigned char *rkey_end;                              /* Real key boundary */
//   unsigned char *ptr;                                   /* Start of the real key*/
//   unsigned char *sptr;                                  /* Start of the working key */
//   unsigned char *key_end = ((unsigned char*)key) + key_length;  /* Working key boundary*/
//
//   rkey_end= rkey + key_size;
//
//   memset(rkey, 0, key_size);          /* Set initial key  */
//
//   for (ptr= rkey, sptr= (unsigned char *)key; sptr < key_end; ptr++, sptr++)
//   {
//     if (ptr == rkey_end)
//       /*  Just loop over tmp_key until we used all key */
//       ptr= rkey;
//     *ptr^= *sptr;
//   }
// }

// bool AesEncrypt(const unsigned char *source, size_t source_length,
//                        unsigned char *dest,
//                        const unsigned char *key, size_t key_length,
//                        const uint8_t *iv) {
//   EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
//   if (!ctx) {
//     return false;
//   }
//
//   const EVP_CIPHER *cipher = EVP_aes_256_cbc();
//
//   /* The real key to be used for encryption */
//   unsigned char rkey[32];
//   //AesCreateKey(key, key_length, rkey);
//
//   const unsigned int key_size = 32;
//   unsigned char *rkey_end;                              /* Real key boundary */
//   unsigned char *ptr;                                   /* Start of the real key*/
//   unsigned char *sptr;                                  /* Start of the working key */
//   unsigned char *key_end = ((unsigned char*)key) + key_length;  /* Working key boundary*/
//
//   rkey_end= rkey + key_size;
//
//   memset(rkey, 0, key_size);          /* Set initial key  */
//
//   for (ptr= rkey, sptr= (unsigned char *)key; sptr < key_end; ptr++, sptr++)
//   {
//     if (ptr == rkey_end)
//       /*  Just loop over tmp_key until we used all key */
//       ptr= rkey;
//     *ptr^= *sptr;
//   }
//
//   if (!cipher || (EVP_CIPHER_iv_length(cipher) > 0 && !iv))
//     return false;
//
//   int u_len, f_len;
//   if (!EVP_EncryptInit(ctx, cipher, rkey, iv))
//     goto aes_error;                             /* Error */
//   if (!EVP_CIPHER_CTX_set_padding(ctx, 1))
//     goto aes_error;                             /* Error */
//   if (!EVP_EncryptUpdate(ctx, dest, &u_len, source, source_length))
//     goto aes_error;                             /* Error */
//   if (!EVP_EncryptFinal_ex(ctx, dest + u_len, &f_len))
//     goto aes_error;                             /* Error */
//
//   EVP_CIPHER_CTX_free(ctx);
//
//   //return u_len + f_len;
//   return false;
//
// aes_error:
//   /* need to explicitly clean up the error if we want to ignore it */
//   ERR_clear_error();
//   EVP_CIPHER_CTX_free(ctx);
//   return false;
// }
//
//
// bool AesDecrypt(const unsigned char *source, size_t source_length,
//                        unsigned char *dest,
//                        const unsigned char *key, size_t key_length,
//                        const uint8_t *iv) {
//   EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
//   if (!ctx) {
//     return false;
//   }
//
//   const EVP_CIPHER *cipher = EVP_aes_256_cbc();
//
//   /* The real key to be used for decryption */
//   unsigned char rkey[32];
//   // AesCreateKey(key, key_length, rkey);
//
//   const unsigned int key_size = 32;
//   unsigned char *rkey_end;                              /* Real key boundary */
//   unsigned char *ptr;                                   /* Start of the real key*/
//   unsigned char *sptr;                                  /* Start of the working key */
//   unsigned char *key_end = ((unsigned char*)key) + key_length;  /* Working key boundary*/
//
//   rkey_end= rkey + key_size;
//
//   memset(rkey, 0, key_size);          /* Set initial key  */
//
//   for (ptr= rkey, sptr= (unsigned char *)key; sptr < key_end; ptr++, sptr++)
//   {
//     if (ptr == rkey_end)
//       /*  Just loop over tmp_key until we used all key */
//       ptr= rkey;
//     *ptr^= *sptr;
//   }
//
//   if (!cipher || (EVP_CIPHER_iv_length(cipher) > 0 && !iv))
//     return false;
//
//   int u_len, f_len;
//   if (!EVP_DecryptInit(ctx, cipher, rkey, iv))
//     goto aes_error;                             /* Error */
//   if (!EVP_CIPHER_CTX_set_padding(ctx, 1))
//     goto aes_error;                             /* Error */
//   if (!EVP_DecryptUpdate(ctx, dest, &u_len, source, source_length))
//     goto aes_error;                             /* Error */
//   if (!EVP_DecryptFinal_ex(ctx, dest + u_len, &f_len))
//     goto aes_error;                             /* Error */
//
//   EVP_CIPHER_CTX_free(ctx);
//
//   //return u_len + f_len;
//   return false;
//
// aes_error:
//   /* need to explicitly clean up the error if we want to ignore it */
//   ERR_clear_error();
//   EVP_CIPHER_CTX_free(ctx);
//   return false;
// }


}  // namespace rocksdb
