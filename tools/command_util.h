// Copyright 2011-2022 Google LLC
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

#include <functional>
#include <vector>

#include "third_party/absl/status/status.h"
#include "third_party/absl/strings/string_view.h"

namespace security::binexport {

// Installs Abseil Flags' library usage callbacks and sets a usage message.
// This needs to be done before any operation that may call one of the
// callbacks such as `absl::ParseCommandLine()` or `ParseSubCommandline()`
// below.
void InstallFlagsUsageConfig(absl::string_view usage_message);

// Returns the full command that was used to launch this sub-command. If not
// set by the launcher, returns "UNKNOWN".
std::string ProgramLaunchCommand();

// Parses command line arguments the same way as `absl::ParseCommandLine()`,
// setting the the program name to indicate which command has been called.
std::vector<char*> ParseSubCommandLine(absl::string_view command, int argc,
                                       char* argv[]);

// Calls a "main" function that returns a status and reports success or failure.
// This allows for unified error handling using `absl::Status`.
int InvokeMainAndReportErrors(
    const std::function<absl::Status(int argc, char* argv[])>& main, int argc,
    char* argv[]);

}  // namespace security::binexport