// Copyright 2011-2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef BINEXPORT2_WRITER_H_
#define BINEXPORT2_WRITER_H_

#include <string>
#include <utility>

#include "third_party/zynamics/binexport/writer.h"

class BinExport2;

namespace security::binexport {

class BinExport2Writer : public Writer {
 public:
  struct Options {
    Options& set_executable_filename(std::string value) {
      executable_filename = std::move(value);
      return *this;
    }

    Options& set_executable_hash(std::string value) {
      executable_hash = std::move(value);
      return *this;
    }

    Options& set_architecture(std::string value) {
      architecture = std::move(value);
      return *this;
    }

    Options& set_export_instruction_raw_bytes(bool value) {
      export_instruction_raw_bytes = value;
      return *this;
    }

    // The filename of the orignal binary.
    std::string executable_filename;

    // Hex-encoded hash of the original binary. Normally, this is a SHA256 hash
    // (64 hex characters) but older versions of IDA Pro may use MD5 instead
    // (32 hex characters). Future versions of BinExport may use different
    // hash algorithms, in which case the format of this string should be
    //   <HASH_ALGO>:<HEX_CHARACTERS>
    std::string executable_hash;

    // A short string describing this binary's instruction set architecure, with
    // the number of address bits appended. Typical values are "x86-64",
    // "ARM-64", and "Dalvik-32". See names.cc's GetArchitectureName().
    std::string architecture;

    // Whether to export the raw bytes making up instructions. Not saving the
    // raw bytes will save significant space in the resulting output.
    bool export_instruction_raw_bytes = false;
  };

  // Note: This writer expects executable_hash to be hex encoded, not the raw
  //       bytes of the digest.
  BinExport2Writer(std::string filename, Options options);

  absl::Status Write(const CallGraph& call_graph, const FlowGraph& flow_graph,
                     const Instructions& instructions,
                     const AddressReferences& address_references,
                     const AddressSpace& address_space) override;

  absl::Status WriteToProto(const CallGraph& call_graph,
                            const FlowGraph& flow_graph,
                            const Instructions& instructions,
                            const AddressReferences& address_references,
                            const AddressSpace& address_space,
                            BinExport2* proto) const;

 private:
  std::string filename_;
  Options options_;
};

}  // namespace security::binexport

#endif  // BINEXPORT2_WRITER_H_
