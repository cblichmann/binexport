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

#include "third_party/zynamics/binexport/tools/command_util.h"

#include <cstdlib>
#include <cstring>

#include "third_party/absl/flags/parse.h"
#include "third_party/absl/flags/usage.h"
#include "third_party/absl/flags/usage_config.h"
#include "third_party/absl/strings/match.h"
#include "third_party/absl/strings/str_cat.h"
#include "third_party/absl/strings/str_format.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/zynamics/binexport/version.h"

namespace security::binexport {

void InstallFlagsUsageConfig(absl::string_view usage_message) {
  absl::SetProgramUsageMessage(usage_message);

  absl::FlagsUsageConfig usage_config;
  usage_config.contains_help_flags = [](absl::string_view filename) {
    return !absl::StartsWith(filename, "core library");
  };
  usage_config.contains_helpshort_flags = usage_config.contains_help_flags;
  usage_config.version_string = []() {
    return absl::StrCat(kBinExportName, " ", kBinExportDetailedVersion, "\n");
  };
  usage_config.normalize_filename =
      [](absl::string_view filename) -> std::string {
    return absl::StartsWith(filename, "absl") ? "core library" : "this binary";
  };
  absl::SetFlagsUsageConfig(usage_config);
}

std::vector<char*> ParseSubCommandLine(absl::string_view command, int argc,
                                       char* argv[]) {
  argv[0] = strdup(absl::StrCat("binexport ", command).c_str());
  std::vector<char*> positional = absl::ParseCommandLine(argc, argv);
  positional.erase(positional.begin());
  return positional;
}

int InvokeMainAndReportErrors(
    const std::function<absl::Status(int argc, char* argv[])>& main, int argc,
    char* argv[]) {
  if (const absl::Status status = main(argc, argv); !status.ok()) {
    absl::FPrintF(stderr, "ERROR: %s\n", status.message());
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}

}  // namespace security::binexport