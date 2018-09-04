// Copyright (c) 2011-present, Facebook, Inc.  All rights reserved.
// This source code is licensed under both the GPLv2 (found in the
// COPYING file in the root directory) and Apache 2.0 License
// (found in the LICENSE.Apache file in the root directory).

#pragma once

#include <condition_variable>
#include <mutex>

namespace rocksdb {
namespace async {

// This class is a helper base which helps
// to convert the async operation into sync
class AsyncAbsorber {
 public:
  AsyncAbsorber(const AsyncAbsorber&) = delete;
  AsyncAbsorber& operator=(const AsyncAbsorber&) = delete;

  // Wait until the callback is absorbed
  void Wait() const {
    std::unique_lock<std::mutex> l(m_);
    while (!signalled_) {
      cvar_.wait(l);
    }
  }

  void Reset() { signalled_ = false; }

 protected:
  AsyncAbsorber() : signalled_(false) {}
  ~AsyncAbsorber() {}

  void Notify() {
    std::unique_lock<std::mutex> l(m_);
    signalled_ = true;
    l.unlock();
    cvar_.notify_one();
  }

 private:
  bool signalled_;
  mutable std::mutex m_;
  mutable std::condition_variable cvar_;
};

}  // namespace async
}  // namespace rocksdb
