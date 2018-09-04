// Copyright (c) 2011-present, Facebook, Inc.  All rights reserved.
// This source code is licensed under both the GPLv2 (found in the
// COPYING file in the root directory) and Apache 2.0 License
// (found in the LICENSE.Apache file in the root directory).

#pragma once

#include "async/async_status_capture.h"
#include "db/db_impl.h"
#include "db/merge_context.h"
#include "db/range_del_aggregator.h"
#include "monitoring/perf_context_imp.h"
#include "rocksdb/async/callables.h"

namespace rocksdb {

class ColumnFamilyData;
class DB;
class DBImpl;
class InternalKeyComparator;
struct ReadOptions;
struct SuperVersion;

namespace async {

namespace db_impl_request_details {
template <typename U, typename B>
inline U* SafeCast(B* b) {
#ifdef _DEBUG
  U* result = dynamic_cast<U*>(b);
  assert(result);
#else
  U* result = reinterpret_cast<U*>(b);
#endif
  return result;
}
}  // namespace db_impl_request_details

// DB::Get() async implementation for DBImpl
class DBImplGetContext : private AsyncStatusCapture {
 public:
  using Callback = Callable<Status, const Status&>;

  static Status RequestGet(const Callback& cb, DB* db,
                           const ReadOptions& read_options,
                           ColumnFamilyHandle* column_family, const Slice& key,
                           PinnableSlice* pinnable_input, std::string* value,
                           bool* value_found = nullptr,
                           ReadCallback* read_cb = nullptr,
                           bool* is_blob_index = nullptr) {
    assert(!pinnable_input || !value);
    DBImpl* db_impl = db_impl_request_details::SafeCast<DBImpl>(db);
    std::unique_ptr<DBImplGetContext> context(new DBImplGetContext(
        cb, db_impl, read_options, key, value, pinnable_input, column_family,
        value_found, read_cb, is_blob_index));
    Status s = context->GetImpl();

    // ??? sagar0
    if (s.IsIOPending()) {
      context.release();
    }
    return s;
  }

  DBImplGetContext(const DBImplGetContext&) = delete;
  DBImplGetContext& operator=(const DBImplGetContext&) = delete;

  DBImplGetContext(const Callback& cb, DBImpl* db, const ReadOptions& ro,
                   const Slice& key, std::string* value,
                   PinnableSlice* pinnable_input,
                   ColumnFamilyHandle* column_family, bool* value_found,
                   ReadCallback* read_cb, bool* is_blob_index);

  ~DBImplGetContext() {
    ReturnSuperVersion();
    GetLookupKey().~LookupKey();
    GetRangeDel().~RangeDelAggregator();
    DestroyPinnableSlice();
  }

 private:
  void InitRangeDelAggreagator(const InternalKeyComparator& icomp,
                               SequenceNumber snapshot) {
    new (&range_del_agg_) RangeDelAggregator(icomp, snapshot);
  }

  RangeDelAggregator& GetRangeDel() {
    return *reinterpret_cast<RangeDelAggregator*>(&range_del_agg_);
  }

  void InitPinnableSlice(PinnableSlice* pinnable_input, std::string* value) {
    if (pinnable_input) {
      pinnable_val_input_ = pinnable_input;
    } else {
      assert(value);
      new (&pinnable_val_) PinnableSlice(value);
    }
  }

  void DestroyPinnableSlice() {
    if (!pinnable_val_input_) {
      reinterpret_cast<PinnableSlice*>(&pinnable_val_)->~PinnableSlice();
    }
  }

  PinnableSlice& GetPinnable() {
    if (pinnable_val_input_) {
      return *pinnable_val_input_;
    }
    return *reinterpret_cast<PinnableSlice*>(&pinnable_val_);
  }

  void InitLookupKey(const Slice& key, SequenceNumber snapshot) {
    new (&lookup_key_) LookupKey(key, snapshot);
  }

  const LookupKey& GetLookupKey() const {
    return *reinterpret_cast<const LookupKey*>(&lookup_key_);
  }

  void ReturnSuperVersion() {
    if (sv_) {
      db_impl_->ReturnAndCleanupSuperVersion(cfd_, sv_);
      sv_ = nullptr;
    }
  }

  Status GetImpl();

  Status OnGetComplete(const Status& status) {
    async(status);
    RecordTick(db_impl_->stats_, MEMTABLE_MISS);
    {
      PERF_TIMER_GUARD(get_post_process_time);
      assert(sv_);
      RecordTick(db_impl_->stats_, NUMBER_KEYS_READ);
      size_t size = GetPinnable().size();
      RecordTick(db_impl_->stats_, BYTES_READ, size);
      MeasureTime(db_impl_->stats_, BYTES_PER_READ, size);
      PERF_COUNTER_ADD(get_read_bytes, size);
    }
    return OnComplete(status);
  }

  Status OnComplete(const Status& status) {
    ReturnSuperVersion();
    // Do this only if we use our own pinnable
    // Otherwise this will be done by a sync
    // entry point
    if (!pinnable_val_input_) {
      if (status.ok() && GetPinnable().IsPinned()) {
        value_->assign(GetPinnable().data(), GetPinnable().size());
      }  // else value is already assigned
    }
    if (cb_ && async()) {
      Status s(status);
      s.async(true);
      cb_.Invoke(s);
      delete this;
      return status;
    }
    return status;
  }

  Callback cb_;
  DBImpl* db_impl_;
  ReadOptions read_options_;
  Slice key_;
  std::string* value_;
  bool* value_found_;
  ReadCallback* read_cb_;
  bool* is_blob_index_;
  ColumnFamilyData* cfd_;
  SuperVersion* sv_;
  StopWatch sw_;
  MergeContext merge_context_;
  PinnableSlice* pinnable_val_input_;  // External for sync
  std::aligned_storage<sizeof(PinnableSlice)>::type pinnable_val_;
  std::aligned_storage<sizeof(RangeDelAggregator)>::type range_del_agg_;
  std::aligned_storage<sizeof(LookupKey)>::type lookup_key_;
};

}  // namespace async
}  // namespace rocksdb
