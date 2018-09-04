// Copyright (c) 2011-present, Facebook, Inc.  All rights reserved.
// This source code is licensed under both the GPLv2 (found in the
// COPYING file in the root directory) and Apache 2.0 License
// (found in the LICENSE.Apache file in the root directory).

#include "db/db_impl_request.h"
#include "util/sync_point.h"

namespace rocksdb {
namespace async {

DBImplGetContext::DBImplGetContext(const Callback& cb, DBImpl* db,
    const ReadOptions& ro, const Slice& key, std::string* value,
    PinnableSlice* pinnable_input, ColumnFamilyHandle* column_family, bool* value_found,
    ReadCallback* read_cb, bool* is_blob_index) :
        cb_(cb), db_impl_(db), read_options_(ro), key_(key), value_(value),
        value_found_(value_found), read_cb_(read_cb),
        is_blob_index_(is_blob_index), cfd_(nullptr), sv_(nullptr),
        sw_(db_impl_->env_, db_impl_->stats_, DB_GET),
        pinnable_val_input_(nullptr) {
  PERF_TIMER_GUARD(get_snapshot_time);

  auto cfh = reinterpret_cast<ColumnFamilyHandleImpl*>(column_family);
  cfd_ = cfh->cfd();

  InitPinnableSlice(pinnable_input, value);
  assert(!GetPinnable().IsPinned());

  // Acquire SuperVersion
  sv_ = db_impl_->GetAndRefSuperVersion(cfd_);

  TEST_SYNC_POINT("DBImpl::GetImpl:1");
  TEST_SYNC_POINT("DBImpl::GetImpl:2");

  SequenceNumber snapshot;
  if (read_options_.snapshot != nullptr) {
    // Note: In WritePrepared txns this is not necessary but not harmful
    // either.  Because prep_seq > snapshot => commit_seq > snapshot so if
    // a snapshot is specified we should be fine with skipping seq numbers
    // that are greater than that.
    //
    // In WriteUnprepared, we cannot set snapshot in the lookup key because we
    // may skip uncommitted data that should be visible to the transaction for
    // reading own writes.
    snapshot =
        reinterpret_cast<const SnapshotImpl*>(read_options_.snapshot)->number_;
    if (read_cb_) {
      snapshot = std::max(snapshot, read_cb_->MaxUnpreparedSequenceNumber());
    }
  } else {
    // Since we get and reference the super version before getting
    // the snapshot number, without a mutex protection, it is possible
    // that a memtable switch happened in the middle and not all the
    // data for this snapshot is available. But it will contain all
    // the data available in the super version we have, which is also
    // a valid snapshot to read from.
    // We shouldn't get snapshot before finding and referencing the super
    // version because a flush happening in between may compact away data for
    // the snapshot, but the snapshot is earlier than the data overwriting it,
    // so users may see wrong results.
    snapshot = db_impl_->last_seq_same_as_publish_seq_
                   ? db_impl_->versions_->LastSequence()
                   : db_impl_->versions_->LastPublishedSequence();
  }

  InitRangeDelAggreagator(cfd_->internal_comparator(), snapshot);
  InitLookupKey(key_, snapshot);

  TEST_SYNC_POINT("DBImpl::GetImpl:3");
  TEST_SYNC_POINT("DBImpl::GetImpl:4");
}

Status DBImplGetContext::GetImpl() {
  Status s;

  // First look in the memtable, then in the immutable memtable (if any).
  // s is both in/out. When in, s could either be OK or MergeInProgress.
  // merge_operands will contain the sequence of merges in the latter case.
  bool skip_memtable = (read_options_.read_tier == kPersistedTier &&
                        db_impl_->has_unpersisted_data_.load(std::memory_order_relaxed));
  bool done = false;
  if (!skip_memtable) {
    if (sv_->mem->Get(GetLookupKey(), GetPinnable().GetSelf(), &s,
                      &merge_context_, &GetRangeDel(), read_options_, read_cb_,
                      is_blob_index_)) {
      done = true;
      GetPinnable().GetSelf();
      RecordTick(db_impl_->stats_, MEMTABLE_HIT);
    } else if ((s.ok() || s.IsMergeInProgress()) &&
               sv_->imm->Get(GetLookupKey(), GetPinnable().GetSelf(), &s,
               &merge_context_, &GetRangeDel(), read_options_, read_cb_,
               is_blob_index_)) {
      done = true;
      GetPinnable().GetSelf();
      RecordTick(db_impl_->stats_, MEMTABLE_HIT);
    }
    if (!done && !s.ok() && !s.IsMergeInProgress()) {
      return OnComplete(s);
    }
  }

  if (!done) {
    PERF_TIMER_GUARD(get_from_output_files_time);
    if (cb_) {
      // CallableFactory<DBImplGetContext, Status, const Status&> fac(this);
      // auto on_get_complete = fac.GetCallable<&DBImplGetContext::OnGetComplete>();
      // s = VersionSetGetContext::RequestGet(on_get_complete, sv_->current,
      //                                     read_options_, GetLookupKey(),
      //                                     &GetPinnable(), &s, &merge_context_,
      //                                     &GetRangeDel(), value_found_, nullptr,
      //                                     nullptr, read_cb_, is_blob_index_);
      sv_->current->Get(read_options_, GetLookupKey(), &GetPinnable(), &s,
                        &merge_context_, &GetRangeDel(), value_found_, nullptr,
                        nullptr, read_cb_, is_blob_index_);
    } else {
      // Sync -- unused for now

      // s = VersionSetGetContext::Get(sv_->current, read_options_, GetLookupKey(),
      //                               &GetPinnable(), &s, &merge_context_,
      //                               &GetRangeDel(), value_found_, nullptr,
      //                               nullptr, read_cb_, is_blob_index_);
    }
    if (s.IsIOPending()) {
      return s;
    }
  }

  return OnGetComplete(s);
}

} // async
} // rocksdb
