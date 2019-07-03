//  Copyright (c) 2011-present, Facebook, Inc.  All rights reserved.
//  This source code is licensed under both the GPLv2 (found in the
//  COPYING file in the root directory) and Apache 2.0 License
//  (found in the LICENSE.Apache file in the root directory).

#include "util/encryption.h"

#ifdef OPENSSL
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#endif

namespace rocksdb {
// Returns encrypted text length
int AesEncrypt(const unsigned char* plaintext,
               const size_t plaintext_length, unsigned char* ciphertext,
               const unsigned char* key, const unsigned char* iv) {
#ifdef OPENSSL
  const EVP_CIPHER* cipher = EVP_aes_256_cbc();
  // const unsigned int kAesKey256SizeInBits = 256;
  // const unsigned int kAesKeySizeInBytes = kAesKey256SizeInBits / 8;
  // const unsigned int kAesBlockizeInBits = 128;

  /* Create and initialize the context */
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    return false;
  }

  if (!cipher || (EVP_CIPHER_iv_length(cipher) > 0 && !iv))
    return false;

  int u_len, f_len;
  /*
   * Initialise the encryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits
   */
  if (1 != EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv)) {
    goto aes_error;                             /* Error */
  }

  // Padding not necessary
  // if (!EVP_CIPHER_CTX_set_padding(ctx, 1)) {
  //   goto aes_error;                             /* Error */
  // }

  /*
   * Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  if (1 !=
      EVP_EncryptUpdate(ctx, ciphertext, &u_len, plaintext, plaintext_length)) {
    goto aes_error;                             /* Error */
  }

  /*
   * Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + u_len, &f_len)) {
    goto aes_error;                             /* Error */
  }

  EVP_CIPHER_CTX_free(ctx);

  return u_len + f_len;

aes_error:
  /* need to explicitly clean up the error if we want to ignore it */
  ERR_clear_error();
  EVP_CIPHER_CTX_free(ctx);
  return 0;
#else
  return 0;
#endif
}

// Returns decrypted text length
int AesDecrypt(const unsigned char *ciphertext,
               const size_t ciphertext_length, unsigned char *plaintext,
               const unsigned char *key, const unsigned char *iv) {
#ifdef OPENSSL
  const EVP_CIPHER *cipher = EVP_aes_256_cbc();
  // const unsigned int kAesKey256SizeInBits = 256;
  // const unsigned int kAesKeySizeInBytes = kAesKey256SizeInBits / 8;
  // const unsigned int kAesBlockizeInBits = 128;

  /* Create and initialize the context */
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    return false;
  }

  if (!cipher || (EVP_CIPHER_iv_length(cipher) > 0 && !iv))
    return false;

  int u_len, f_len;
  /*
   * Initialise the decryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits
   */
  if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv)) {
    goto aes_error;                             /* Error */
  }

  // Padding not necessary
  // if (!EVP_CIPHER_CTX_set_padding(ctx, 1)) {
  //   goto aes_error;                             /* Error */
  // }

  /*
   * Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary.
   */
  if (1 != EVP_DecryptUpdate(ctx, plaintext, &u_len, ciphertext,
                             ciphertext_length)) {
    goto aes_error;                             /* Error */
  }

  /*
   * Finalise the decryption. Further plaintext bytes may be written at
   * this stage.
   */
  if (1 != EVP_DecryptFinal_ex(ctx, plaintext + u_len, &f_len)) {
    goto aes_error;                             /* Error */
  }

  EVP_CIPHER_CTX_free(ctx);

  return u_len + f_len;

aes_error:
  /* need to explicitly clean up the error if we want to ignore it */
  ERR_clear_error();
  EVP_CIPHER_CTX_free(ctx);
  return 0;
#else
  return 0;
#endif
}
}
