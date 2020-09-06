// Copyright 2011-2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Disassemble an x86 binary using Zydis and save it in BinExport2 format.

#include <cstring>
#include <fstream>
#include <memory>
#include <sstream>
#include <vector>

#include "third_party/absl/status/status.h"
#include "third_party/absl/strings/match.h"
#include "third_party/absl/strings/str_cat.h"
#include "third_party/absl/strings/str_format.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/zynamics/binexport/binexport.h"
#include "third_party/zynamics/binexport/binexport2.pb.h"
#include "third_party/zynamics/binexport/tools/command_util.h"
#include "third_party/zynamics/binexport/util/filesystem.h"
#include "third_party/zynamics/binexport/util/status_macros.h"
#include "third_party/zynamics/binexport/util/statusor.h"

#include <Zydis/Zydis.h>
#include "openssl/sha.h"

namespace security::binexport {
namespace {

namespace file {

not_absl::StatusOr<std::string> GetContents(absl::string_view path) {
  std::ifstream in_stream(std::string(path), std::ios_base::binary);
  std::ostringstream out_stream;
  out_stream << in_stream.rdbuf();
  if (!in_stream || !out_stream) {
    return absl::UnknownError(absl::StrCat("Reading ", path));
  }
  return out_stream.str();
}

}  // namespace file

constexpr absl::string_view kElfMagic =
    "\x7F"
    "ELF";

absl::Status DisasmMain(int argc, char* argv[]) {
  InstallFlagsUsageConfig("Disassemble a binary into BinExport format.");
  std::vector<char*> positional = ParseSubCommandLine("disasm", argc, argv);

  if (positional.size() != 2) {
    return absl::FailedPreconditionError("Missing input/output files");
  }

  // Master plan:
  // - Open file, check type (ELF/PE)
  //   - Not x86/x86-64? -> error
  // - Parse executable image, find all functions
  //   - Add entry-point
  //   - Add each function as entry-point
  // - Analyze flow
  // - Write to BinExport file

  NA_ASSIGN_OR_RETURN(std::string input_binary,
                      file::GetContents(positional[0]));
  if (!absl::StartsWith(input_binary, kElfMagic)) {
    return absl::FailedPreconditionError("Input file not an ELF image");
  }

  ZydisDecoder decoder;
  ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64,
                   ZYDIS_ADDRESS_WIDTH_64);

  return absl::OkStatus();
}

}  // namespace
}  // namespace security::binexport

int main(int argc, char* argv[]) {
  return security::binexport::InvokeMainAndReportErrors(
      security::binexport::DisasmMain, argc, argv);
}
