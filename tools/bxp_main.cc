// Copyright 2011-2021 Google LLC
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

// Entry point for BinExport command-line utilities.

#include <codecvt>  // For GetModuleFilename
#include <locale>   // For GetModuleFilename
#include <vector>

#include "third_party/absl/flags/flag.h"
#include "third_party/absl/flags/parse.h"
#include "third_party/absl/flags/usage.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/strings/match.h"
#include "third_party/absl/strings/str_cat.h"
#include "third_party/absl/strings/str_format.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/zynamics/binexport/tools/command_util.h"
#include "third_party/zynamics/binexport/util/filesystem.h"
#include "third_party/zynamics/binexport/util/process.h"
#include "third_party/zynamics/binexport/util/status_macros.h"

namespace security::binexport {
namespace {

// Finds the first non-flag argument. This needs to be called before Abseil's
// command-line processing because Abseil automatically handles default flags
// and may exit the program for unknown arguments.
// Returns the index of the first non-flag argument, or argc if there is no such
// argument.
int FindSubCommand(int argc, char* argv[]) {
  for (int i = 1; i < argc; ++i) {
    absl::string_view arg = argv[i];
    if (!absl::StartsWith(arg, "-")) {
      return i;
    }
  }
  return argc;
}

// Returns the full path of the currently running executable.
absl::StatusOr<std::string> GetModuleFilename() {
  // TODO(cblichmann): Move to process.cc
#ifdef _WIN32
  // TODO(cblichmann): Test/compile this
  std::wstring path(MAX_PATH, L'\0');
  while (true) {
    const DWORD len =
        GetModuleFileNameW(nullptr, &path[0], static_cast<DWORD>(path.size()));
    if (len == 0 && GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
      return absl::UnknownError(
          absl::StrCat("Failed to get module path: ", GetLastOsError()));
    }
    if (len < path.size()) {
      path.resize(len);
      break;
    }
    path.resize(3 * path.size() / 2);
  }
  return std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(path);
#elif __APPLE__
  // TODO(cblichmann): Test/compile this
  std::string path(NAME_MAX, '\0');  // Start small
  while (true) {
    if (_NSGetExecutablePath(&path[0], path.size() == 0) {
      path.resize(strlen(&path[0]));
      break;
    }
    path.resize(3 * path.size() / 2);
  }
#else
  std::string path(NAME_MAX, '\0');  // Start small
  while (true) {
    ssize_t len = readlink("/proc/self/exe", &path[0], path.size());
    if (len < 0) {
      return absl::UnknownError(
          absl::StrCat("Failed to get module path: ", GetLastOsError()));
    }
    if (len < path.size()) {
      path.resize(len);
      break;
    }
    path.resize(3 * path.size() / 2);
  }
#endif
  return path;
}

const std::string& GetLookupDir() {
  static const auto* lookup_dir =
      new std::string(Dirname(GetModuleFilename().value_or("")));
  return *lookup_dir;
}

constexpr absl::string_view kToolPrefix = "bxp-";

absl::StatusOr<std::string> ValidateCommand(absl::string_view command) {
  if (std::string command_exe =
          JoinPath(GetLookupDir(), absl::StrCat(kToolPrefix, command));
      FileExists(command_exe)) {
    return command_exe;
  }
  return absl::NotFoundError(absl::StrCat(
      "'", command, "' is not a binexport command. See 'bxp --help'."));
}

absl::Status BxpMain(int argc, char* argv[]) {
  InstallFlagsUsageConfig("Create/work with exported disassembly files.");

  int command_index = FindSubCommand(argc, argv);
  if (command_index == argc) {
    return absl::InvalidArgumentError("No command given. Try '--help'.");
  }
  if (command_index != 1) {
    // Handle options specified before any sub-command.
    absl::ParseCommandLine(argc - command_index, argv);
  }

  NA_ASSIGN_OR_RETURN(const std::string command_exe,
                      ValidateCommand(argv[command_index]));

  std::vector<std::string> command_args({command_exe});
  command_args.reserve(argc - command_index - 1);
  for (int i = command_index + 1; i < argc; ++i) {
    command_args.push_back(argv[i]);
  }
  NA_RETURN_IF_ERROR(SpawnProcessAndWait(command_args).status());

  return absl::OkStatus();
}

}  // namespace
}  // namespace security::binexport

int main(int argc, char* argv[]) {
  return security::binexport::InvokeMainAndReportErrors(
      security::binexport::BxpMain, argc, argv);
}