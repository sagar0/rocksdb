//  Copyright (c) 2011-present, Facebook, Inc.  All rights reserved.
//  This source code is licensed under both the GPLv2 (found in the
//  COPYING file in the root directory) and Apache 2.0 License
//  (found in the LICENSE.Apache file in the root directory).

#pragma once

#include <cstddef>

namespace rocksdb {

int AesEncrypt(const unsigned char* plaintext,
               const size_t plaintext_length, unsigned char* ciphertext,
               const unsigned char* key, const unsigned char* iv);

int AesDecrypt(const unsigned char *ciphertext,
               const size_t ciphertext_length, unsigned char *plaintext,
               const unsigned char *key, const unsigned char *iv);

}  // namespace rocksdb
