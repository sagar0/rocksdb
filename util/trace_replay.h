//  Copyright (c) 2011-present, Facebook, Inc.  All rights reserved.
//  This source code is licensed under both the GPLv2 (found in the
//  COPYING file in the root directory) and Apache 2.0 License
//  (found in the LICENSE.Apache file in the root directory).

#pragma once

#include <memory>
#include <unordered_map>
#include <utility>

#include "rocksdb/env.h"
#include "rocksdb/utilities/trace_reader_writer.h"

namespace rocksdb {

class ColumnFamilyHandle;
class DBImpl;
class RandomAccessFileReader;
class Slice;
class WritableFileWriter;
class WriteBatch;

enum TraceType : char {
  kTraceBegin = 1,
  kTraceEnd = 2,
  kTraceWrite = 3,
  kTraceGet = 4,
  kTraceMax,
};

struct Trace {
  uint64_t ts;
  TraceType type;
  std::string payload;

  void reset() {
    ts = 0;
    type = kTraceMax;
    payload.clear();
  }
};

class Tracer {
 public:
  Tracer(Env* env, std::unique_ptr<TraceWriter>&& trace_writer);
  ~Tracer();

  Status Write(WriteBatch* write_batch);
  Status Get(ColumnFamilyHandle* cfname, const Slice& key);

  Status Close();

 private:
  Status WriteHeader();
  Status WriteFooter();
  Status WriteTrace(Trace& trace);

  Env* env_;
  unique_ptr<TraceWriter> trace_writer_;
};

class Replayer {
 public:
  Replayer(DBImpl* db, std::vector<ColumnFamilyHandle*>& handles,
           std::unique_ptr<TraceReader>&& reader);
  ~Replayer();

 private:
  Status Replay();

  Status ReadHeader(Trace& header);
  Status ReadFooter(Trace& footer);
  Status ReadTrace(Trace& trace);

  DBImpl* db_;
  std::unique_ptr<TraceReader> trace_reader_;
  std::unordered_map<uint32_t, ColumnFamilyHandle*> cf_map_;
};

class FileTraceReader : public TraceReader {
 public:
  FileTraceReader(std::unique_ptr<RandomAccessFileReader>&& reader);
  ~FileTraceReader();

  virtual Status Read(std::string* data) override;
  virtual Status Close() override;

 private:
  unique_ptr<RandomAccessFileReader> file_reader_;
  Slice result_;
  size_t offset_;
  char* const buffer_;

  static const unsigned int kBufferSize;
};

class FileTraceWriter : public TraceWriter {
 public:
  FileTraceWriter(Env* env, std::unique_ptr<WritableFileWriter>&& file_writer)
      : env_(env), file_writer_(std::move(file_writer)) {}
  ~FileTraceWriter();

  virtual Status Write(const Slice& data) override;
  virtual Status Close() override;

 private:
  Env* env_;
  unique_ptr<WritableFileWriter> file_writer_;
};

}  // namespace rocksdb
