// Copyright 2021 Google LLC
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

#ifndef BINARYNINJA_ANALYSIS_H_
#define BINARYNINJA_ANALYSIS_H_

// clang-format off
#include "binaryninjaapi.h"  // NOLINT
// clang-format on

#include "third_party/absl/status/status.h"
#include "third_party/zynamics/binexport/entry_point.h"
#include "third_party/zynamics/binexport/instruction.h"
#include "third_party/zynamics/binexport/call_graph.h"
#include "third_party/zynamics/binexport/flow_graph.h"
#include "third_party/zynamics/binexport/writer.h"

namespace security::binexport {

absl::Status AnalyzeFlowBinaryNinja(BinaryNinja::BinaryView* view,
                                    EntryPoints* entry_points, Writer* writer,
                                    detego::Instructions* instructions,
                                    FlowGraph* flow_graph,
                                    CallGraph* call_graph);

}  // namespace security::binexport

#endif  // BINARYNINJA_ANALYSIS_H_
