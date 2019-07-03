//  Copyright (c) 2011-present, Facebook, Inc.  All rights reserved.
//  This source code is licensed under both the GPLv2 (found in the
//  COPYING file in the root directory) and Apache 2.0 License
//  (found in the LICENSE.Apache file in the root directory).

#pragma once

#include <cstddef>
#include "rocksdb/options.h"

namespace rocksdb {

int AesEncrypt(const unsigned char* plaintext,
               const size_t plaintext_length, unsigned char* ciphertext,
               const EncryptionType cipher_type, const unsigned char* key, const unsigned char* iv);

int AesDecrypt(const unsigned char *ciphertext,
               const size_t ciphertext_length, unsigned char *plaintext,
               const EncryptionType cipher_type, const unsigned char *key, const unsigned char *iv);

inline std::string EncryptionTypeToString(EncryptionType encryption_type) {
  switch (encryption_type) {
    case kNoEncryption:
      return "NoEncryption";
    case kAES128:
      return "AES128";
    case kAES192:
      return "AES192";
    case kAES256:
      return "AES256";
    default:
      assert(false);
      return "";
  }
}

inline enum EncryptionType StringToEncryptionType(std::string str) {
  if (str.empty() || str == " " || str == "NoEncryption") {
    return kNoEncryption;
  } else if (str == "AES128") {
    return kAES128;
  } else if (str == "AES192") {
    return kAES192;
  } else if (str == "AES256") {
    return kAES256;
  }
  return kNoEncryption;
}

}  // namespace rocksdb
