// Copyright 2019-2021 Google LLC
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

#include "third_party/zynamics/binexport/binaryninja/main_plugin.h"

#include <cstdint>
#include <string>

#include "base/logging.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/status/statusor.h"
#include "third_party/absl/strings/escaping.h"
#include "third_party/absl/strings/match.h"
#include "third_party/absl/strings/str_cat.h"
#include "third_party/absl/strings/str_format.h"
#include "third_party/zynamics/binexport/binaryninja/flow_analysis.h"
#include "third_party/zynamics/binexport/binaryninja/log_sink.h"
#include "third_party/zynamics/binexport/binexport2_writer.h"
#include "third_party/zynamics/binexport/call_graph.h"
#include "third_party/zynamics/binexport/entry_point.h"
#include "third_party/zynamics/binexport/flow_analysis.h"
#include "third_party/zynamics/binexport/flow_graph.h"
#include "third_party/zynamics/binexport/instruction.h"
#include "third_party/zynamics/binexport/util/filesystem.h"
#include "third_party/zynamics/binexport/util/format.h"
#include "third_party/zynamics/binexport/util/logging.h"
#include "third_party/zynamics/binexport/util/status_macros.h"
#include "third_party/zynamics/binexport/util/timer.h"
#include "third_party/zynamics/binexport/version.h"

namespace security::binexport {

absl::StatusOr<std::string> GetInputFileSha256(BinaryNinja::BinaryView* view) {
  auto transform = BinaryNinja::Transform::GetByName("SHA256");
  if (!transform) {
    return absl::FailedPreconditionError("SHA256 not available");
  }

  auto raw_view = view->GetParentView();
  if (!raw_view) {
    return absl::InternalError("Failed to load SHA256 hash of input file");
  }
  BinaryNinja::DataBuffer buffer =
      raw_view->ReadBuffer(0, raw_view->GetLength());

  BinaryNinja::DataBuffer sha256_hash(32);
  if (!transform->Encode(buffer, sha256_hash)) {
    return absl::UnknownError("SHA256 transform failed");
  }

  return absl::BytesToHexString(
      absl::string_view(static_cast<const char*>(sha256_hash.GetData()),
                        sha256_hash.GetLength()));
}

std::string GetArchitectureName(BinaryNinja::BinaryView* view) {
  auto default_arch = view->GetDefaultArchitecture();
  std::string name = default_arch->GetName();
  std::string architecture;
  if (absl::StartsWith(name, "x86")) {
    architecture = "x86";
  } else if (absl::StartsWith(name, "arm") || name == "aarch64") {
    architecture = "ARM";
  } else if (absl::StartsWith(name, "mips")) {
    architecture = "MIPS";
  } else if (name == "ppc64") {
    architecture = "PowerPC";
  } else {
    architecture = "GENERIC";
  }

  if (default_arch->GetAddressSize() == 8) {
    absl::StrAppend(&architecture, "-64");
  } else if (default_arch->GetAddressSize() == 4) {
    absl::StrAppend(&architecture, "-32");
  }
  return architecture;
}

absl::Status ExportBinaryView(BinaryNinja::BinaryView* view, Writer* writer) {
  const std::string filename = view->GetFile()->GetOriginalFilename();
  LOG(INFO) << filename << ": starting export";
  Timer<> timer;
  EntryPoints entry_points;

  {
    EntryPointManager function_manager(&entry_points, "functions");
    EntryPointManager call_manager(&entry_points, "calls");
    for (const auto& func_ref : view->GetAnalysisFunctionList()) {
      auto symbol_ref = func_ref->GetSymbol();
      switch (symbol_ref->GetType()) {
        case BNSymbolType::FunctionSymbol:
          function_manager.Add(symbol_ref->GetAddress(),
                               EntryPoint::Source::FUNCTION_PROLOGUE);
          break;
        case BNSymbolType::ImportedFunctionSymbol:
          call_manager.Add(symbol_ref->GetAddress(),
                           EntryPoint::Source::CALL_TARGET);
          break;
        default:
          LOG(WARNING) << symbol_ref->GetShortName()
                       << " has unimplemented type " << symbol_ref->GetType();
      }
    }
  }

  Instructions instructions;
  FlowGraph flow_graph;
  CallGraph call_graph;
  NA_RETURN_IF_ERROR(AnalyzeFlowBinaryNinja(
      view, &entry_points, writer, &instructions, &flow_graph, &call_graph));

  LOG(INFO) << absl::StrCat(
      filename, ": exported ", flow_graph.GetFunctions().size(),
      " functions with ", instructions.size(), " instructions in ",
      HumanReadableDuration(timer.elapsed()));
  return absl::OkStatus();
}

absl::Status ExportBinary(const std::string& filename,
                          BinaryNinja::BinaryView* view) {
  NA_ASSIGN_OR_RETURN(std::string sha256_hash, GetInputFileSha256(view));

  BinExport2Writer writer(filename, view->GetFile()->GetOriginalFilename(),
                          sha256_hash, GetArchitectureName(view));
  NA_RETURN_IF_ERROR(ExportBinaryView(view, &writer));
  return absl::OkStatus();
}

void Plugin::Run(BinaryNinja::BinaryView* view) {
  const std::string filename =
      ReplaceFileExtension(view->GetFile()->GetFilename(), ".BinExport");
  if (auto status = ExportBinary(filename, view); !status.ok()) {
    LOG(ERROR) << "Error exporting: " << std::string(status.message());
  }
}

bool Plugin::Init() {
  if (auto status = InitLogging(LoggingOptions{},
                                absl::make_unique<BinaryNinjaLogSink>());
      !status.ok()) {
    BinaryNinja::LogError(
        "Error initializing logging, skipping BinExport plugin: %s",
        std::string(status.message()).c_str());
    return false;
  }

  LOG(INFO) << kBinExportName << " " << kBinExportDetailedVersion << ", "
            << kBinExportCopyright;

  BinaryNinja::PluginCommand::Register(
      kBinExportName, kDescription,
      [](BinaryNinja::BinaryView* view) { Plugin::instance()->Run(view); });

  return true;
}

}  // namespace security::binexport

extern "C" BINARYNINJAPLUGIN uint32_t CorePluginABIVersion() {
  // BinExport should work on both channels of the 2.x series as it only uses
  // API functions that have remained relatively stable.
  // Note: This works around Binary Ninja's ABI version handling and BinExport
  //       will fail to load with an error message if the "dev" channel diverges
  //       too far from stable. However, users on "dev" should expect some
  //       breakage and failing to load the plugin still leaves Binary Ninja
  //       functional.
  return BNGetMinimumCoreABIVersion();
}

extern "C" BINARYNINJAPLUGIN bool CorePluginInit() {
  return security::binexport::Plugin::instance()->Init();
}
