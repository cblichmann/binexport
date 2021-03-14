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

// Export sub-sets of functions to JSON.

#include <google/protobuf/util/json_util.h>

#ifndef _WIN32
#include <unistd.h>  //isatty()
#else
#include <io.h>  // _isatty()
#define isatty _isatty
#endif

#include <cstdio>  // fileno()
#include <cstring>
#include <type_traits>
#include <vector>

#include "third_party/absl/container/btree_map.h"
#include "third_party/absl/container/flat_hash_map.h"
#include "third_party/absl/container/flat_hash_set.h"
#include "third_party/absl/flags/flag.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/strings/str_cat.h"
#include "third_party/absl/strings/str_format.h"
#include "third_party/absl/strings/string_view.h"
#include "third_party/absl/types/span.h"
#include "third_party/zynamics/binexport/binexport.h"
#include "third_party/zynamics/binexport/binexport2.pb.h"
#include "third_party/zynamics/binexport/tools/command_util.h"
#include "third_party/zynamics/binexport/util/format.h"
#include "third_party/zynamics/binexport/util/status_macros.h"

namespace security::binexport {

enum class OutputFormat {
  kJson,
  kBinary,  // BinExport v2 proto
};

bool AbslParseFlag(absl::string_view text, OutputFormat* mode,
                   std::string* error) {
  if (text == "json") {
    *mode = OutputFormat::kJson;
    return true;
  }
  if (text == "binary") {
    *mode = OutputFormat::kBinary;
    return true;
  }
  *error = "unknown value for enumeration";
  return false;
}

std::string AbslUnparseFlag(OutputFormat mode) {
  switch (mode) {
    case OutputFormat::kJson:
      return "json";
    case OutputFormat::kBinary:
      return "binary";
    default:
      return absl::StrCat(mode);
  }
}

}  // namespace security::binexport

ABSL_FLAG(security::binexport::OutputFormat, format,
          security::binexport::OutputFormat::kJson,
          "output format, one of 'json', 'binary'");
ABSL_FLAG(bool, pretty_print, false, "pretty print JSON output");

namespace security::binexport {
namespace {

Address GetFunctionEntryPoint(const BinExport2& proto,
                              const BinExport2::FlowGraph& flow_graph) {
  return GetInstructionAddress(
      proto, proto.basic_block(flow_graph.entry_basic_block_index())
                 .instruction_index(0)
                 .begin_index());
}

const BinExport2::FlowGraph* GetFunction(const BinExport2& proto,
                                         Address address) {
  // Ordinarily, the flow graphs are sorted by entry point address in ascending
  // order. However, this is not enforced anywhere in the format and the Ghidra
  // exporter may not sort the flow graphs. So we have to do a linear scan here.
  for (const auto& flow_graph : proto.flow_graph()) {
    if (GetFunctionEntryPoint(proto, flow_graph) == address) {
      return &flow_graph;
    }
  }
  return nullptr;
}

const BinExport2::CallGraph::Vertex* GetFunctionVertex(const BinExport2& proto,
                                                       Address address) {
  // See comment in GetFunction(), call graph vertices should also be stored
  // in ascending address order.
  for (auto& vertex : proto.call_graph().vertex()) {
    if (vertex.address() == address) {
      return &vertex;
    }
  }
  return nullptr;
}

absl::StatusOr<BinExport2> ExtractFunction(const BinExport2& proto,
                                           Address function_address) {
  auto* const flow_graph = GetFunction(proto, function_address);
  if (!flow_graph) {
    return absl::NotFoundError(absl::StrCat("no function at address ",
                                            FormatAddress(function_address)));
  }

  BinExport2 to_proto;
  auto* to_metadata = to_proto.mutable_meta_information();
  // Copy metadata. Specifically, we need to set the architecture name as that
  // determines how size prefixes are rendered.
  *to_metadata = proto.meta_information();
  // Update timestamp
  to_metadata->set_timestamp(absl::ToUnixSeconds(absl::Now()));

  auto* to_vertex = to_proto.mutable_call_graph()->add_vertex();
  to_vertex->set_address(function_address);
  if (auto* vertex = GetFunctionVertex(proto, function_address)) {
    if (vertex->has_mangled_name()) {
      to_vertex->set_mangled_name(vertex->mangled_name());
    }
    if (vertex->has_demangled_name()) {
      to_vertex->set_demangled_name(vertex->demangled_name());
    }
  }

  // These maps record which entities are referenced by this function. They map
  // ids in the source proto to ids in to_proto.
  absl::flat_hash_map<int, int> referenced_basic_blocks;
  absl::flat_hash_map<int, int> referenced_instructions;
  absl::flat_hash_map<int, int> referenced_mnemonics;
  absl::flat_hash_map<int, int> referenced_operands;
  absl::flat_hash_map<int, int> referenced_expressions;
  absl::flat_hash_map<int, int> referenced_comments;
  absl::flat_hash_map<int, int> referenced_strings;
  int bb_id = 0;
  int instr_id = 0;
  int mnem_id = 0;
  int op_id = 0;
  int expr_id = 0;
  int comment_id = 0;
  int str_id = 0;

  to_proto.mutable_basic_block()->Reserve(flow_graph->basic_block_index_size());
  for (int bb_index : flow_graph->basic_block_index()) {
    to_proto.add_basic_block();
    referenced_basic_blocks[bb_index] = bb_id++;

    const auto& basic_block = proto.basic_block(bb_index);
    for (const auto& range : basic_block.instruction_index()) {
      int begin_index = range.begin_index();
      int end_index =
          range.has_end_index() ? range.end_index() : begin_index + 1;
      for (int i = begin_index; i < end_index; ++i) {
        if (referenced_instructions.emplace(i, instr_id).second) {
          ++instr_id;
        }
      }
    }
  }

  const int num_instructions = referenced_instructions.size();
  to_proto.mutable_instruction()->Reserve(num_instructions);
  // Heuristic: assume 2 expressions and operands per instruction
  to_proto.mutable_expression()->Reserve(num_instructions * 2);
  to_proto.mutable_operand()->Reserve(num_instructions * 2);
  for (const auto& [from, to] : referenced_instructions) {
    to_proto.add_instruction();
    const auto& instruction = proto.instruction(from);
    if (int mnem_index = instruction.mnemonic_index();
        referenced_mnemonics.emplace(mnem_index, mnem_id).second) {
      // Set the mnemonics directly, as they are distinct from the string table.
      to_proto.add_mnemonic()->set_name(proto.mnemonic(mnem_index).name());
      ++mnem_id;
    }
    for (int op_index : instruction.operand_index()) {
      if (referenced_operands.emplace(op_index, op_id).second) {
        to_proto.add_operand();
        ++op_id;
      }
    }
    for (int comment_index : instruction.comment_index()) {
      if (referenced_comments.emplace(comment_index, comment_id).second) {
        ++comment_id;
      }
    }
  }

  for (const auto& [from, to] : referenced_operands) {
    const auto& operand = proto.operand(from);
    for (int expr_index : operand.expression_index()) {
      if (referenced_expressions.emplace(expr_index, expr_id).second) {
        to_proto.add_expression();
        ++expr_id;
      }
    }
  }

  to_proto.mutable_comment()->Reserve(referenced_comments.size());
  for (const auto& [from, to] : referenced_comments) {
    const auto& comment = proto.comment(from);
    to_proto.add_comment();
    if (comment.has_string_table_index() &&
        referenced_strings.emplace(comment.string_table_index(), str_id)
            .second) {
      to_proto.add_string_table(
          proto.string_table(comment.string_table_index()));
      ++str_id;
    }
  }

  // From here on, all referenced entities are available. Start assembling the
  // output BinExport2 proto.

  for (const auto& [from, to] : referenced_expressions) {
    const auto& expression = proto.expression(from);
    auto* to_expression = to_proto.mutable_expression(to);
    if (expression.has_type()) {
      to_expression->set_type(expression.type());
    }
    if (expression.has_symbol()) {
      to_expression->set_symbol(expression.symbol());
    }
    if (expression.has_immediate()) {
      to_expression->set_immediate(expression.immediate());
    }
    if (expression.has_parent_index()) {
      to_expression->set_parent_index(
          referenced_expressions[expression.parent_index()]);
    }
    if (expression.has_is_relocation()) {
      to_expression->set_is_relocation(expression.is_relocation());
    }
  }

  for (const auto& [from, to] : referenced_operands) {
    const auto& operand = proto.operand(from);
    auto* to_operand = to_proto.mutable_operand(to);
    for (int expr_index : operand.expression_index()) {
      to_operand->add_expression_index(referenced_expressions[expr_index]);
    }
  }

  for (const auto& [from, to] : referenced_comments) {
    const auto& comment = proto.comment(from);
    auto* to_comment = to_proto.mutable_comment(to);
    if (comment.has_instruction_index()) {
      to_comment->set_instruction_index(
          referenced_instructions[comment.instruction_index()]);
    }
    if (comment.has_instruction_operand_index()) {
      to_comment->set_instruction_operand_index(
          referenced_operands[comment.instruction_operand_index()]);
    }
    if (comment.has_operand_expression_index()) {
      to_comment->set_operand_expression_index(
          referenced_expressions[comment.operand_expression_index()]);
    }
    if (comment.has_string_table_index()) {
      to_comment->set_string_table_index(
          referenced_strings[comment.string_table_index()]);
    }
    if (comment.has_repeatable()) {
      to_comment->set_repeatable(comment.repeatable());
    }
    if (comment.has_type()) {
      to_comment->set_type(comment.type());
    }
  }

  to_proto.mutable_instruction()->Reserve(instr_id);
  for (const auto& [from, to] : referenced_instructions) {
    const auto& instruction = proto.instruction(from);
    auto* to_instruction = to_proto.mutable_instruction(to);

    if (instruction.has_address()) {
      to_instruction->set_address(instruction.address());
    }
    *to_instruction->mutable_call_target() = instruction.call_target();
    // Need to set unconditionally here. The most common instruction in this
    // function will usually not be the same as for the whole binary.
    to_instruction->set_mnemonic_index(
        referenced_mnemonics[instruction.mnemonic_index()]);
    for (int operand_index : instruction.operand_index()) {
      to_instruction->add_operand_index(referenced_operands[operand_index]);
    }
    *to_instruction->mutable_raw_bytes() = instruction.raw_bytes();
    for (int comment_index : instruction.comment_index()) {
      to_instruction->add_comment_index(referenced_comments[comment_index]);
    }
  }

  for (const auto& [from, to] : referenced_basic_blocks) {
    const auto& basic_block = proto.basic_block(from);
    auto* to_basic_block = to_proto.mutable_basic_block(to);
    for (const auto& instruction_index : basic_block.instruction_index()) {
      auto* to_instruction_index = to_basic_block->add_instruction_index();
      if (instruction_index.has_begin_index()) {
        to_instruction_index->set_begin_index(
            referenced_instructions[instruction_index.begin_index()]);
      }
      if (instruction_index.has_end_index()) {
        to_instruction_index->set_end_index(
            referenced_instructions[instruction_index.end_index()]);
      }
    }
  }

  auto* to_flow_graph = to_proto.add_flow_graph();
  to_flow_graph->mutable_basic_block_index()->Reserve(
      referenced_basic_blocks.size());
  for (int basic_block_index : flow_graph->basic_block_index()) {
    to_flow_graph->add_basic_block_index(
        referenced_basic_blocks[basic_block_index]);
  }
  if (flow_graph->has_entry_basic_block_index()) {
    to_flow_graph->set_entry_basic_block_index(
        referenced_basic_blocks[flow_graph->entry_basic_block_index()]);
  }
  to_flow_graph->mutable_edge()->Reserve(flow_graph->edge_size());
  for (const auto& edge : flow_graph->edge()) {
    auto* to_edge = to_flow_graph->add_edge();
    if (edge.has_source_basic_block_index()) {
      to_edge->set_source_basic_block_index(
          referenced_basic_blocks[edge.source_basic_block_index()]);
    }
    if (edge.has_target_basic_block_index()) {
      to_edge->set_target_basic_block_index(
          referenced_basic_blocks[edge.target_basic_block_index()]);
    }
    if (edge.has_type()) {
      to_edge->set_type(edge.type());
    }
    if (edge.has_is_back_edge()) {
      to_edge->set_is_back_edge(edge.is_back_edge());
    }
  }

  return to_proto;
}

// TODO(cblichmann): Use absl::SimpleHexAtoi() once available
bool SimpleHexAtoi(const char* s, uint64_t* out) {
  char* s_end;
  *out = std::strtoul(  // NOLINT(runtime/deprecated_fn
      s, &s_end, 16);
  return errno != ERANGE && (s_end == s + strlen(s));
}

absl::Status FlowGraphMain(int argc, char* argv[]) {
  using AutoClosingFile = std::unique_ptr<std::FILE, void (*)(std::FILE*)>;
  auto file_closer = [](std::FILE* fp) {
    if (fp) {
      std::fclose(fp);
    }
  };

  InstallFlagsUsageConfig(
      "Export single flow graphs from a BinExport v2 file.\n"
      "Usage: bxp flow-graph [OPTION] BINEXPORT2 ADDRESS [OUTFILE]");
  std::vector<char*> positional = ParseSubCommandLine("flow-graph", argc, argv);

  if (positional.size() < 2) {
    return absl::InvalidArgumentError("missing operand(s)");
  }

  Address function_address;
  if (!SimpleHexAtoi(positional[1], &function_address)) {
    return absl::InvalidArgumentError(
        absl::StrCat("not a valid hex number: ", positional[1]));
  }

  BinExport2 proto;
  {
    AutoClosingFile file(std::fopen(positional[0], "rb"), file_closer);
    if (!file) {
      return absl::FailedPreconditionError(
          absl::StrCat("could not open file: ", strerror(errno)));
    }
    if (!proto.ParseFromFileDescriptor(fileno(file.get()))) {
      return absl::FailedPreconditionError("failed to parse BinExport v2 data");
    }
  }

  NA_ASSIGN_OR_RETURN(BinExport2 function_proto,
                      ExtractFunction(proto, function_address));

  AutoClosingFile outfile(nullptr, file_closer);
  if (positional.size() == 3) {
    outfile.reset(std::fopen(positional[2], "wb"));
    if (!outfile) {
      return absl::FailedPreconditionError(
          absl::StrCat("could not open file: ", strerror(errno)));
    }
  }

  switch (absl::GetFlag(FLAGS_format)) {
    case OutputFormat::kJson: {
      std::string json;
      google::protobuf::util::JsonOptions json_options;
      json_options.add_whitespace = absl::GetFlag(FLAGS_pretty_print);
      json_options.always_print_enums_as_ints =
          !absl::GetFlag(FLAGS_pretty_print);
      google::protobuf::util::MessageToJsonString(function_proto, &json,
                                                  json_options);
      std::fwrite(json.c_str(), json.size(), 1,
                  outfile ? outfile.get() : stdout);
    }
    case OutputFormat::kBinary:
    default:
      if (!outfile && isatty(fileno(stdout))) {
        return absl::CancelledError(
            "refusing to write binary data to terminal");
      }
      function_proto.SerializeToFileDescriptor(
          fileno(outfile ? outfile.get() : stdout));
  }

  return absl::OkStatus();
}

}  // namespace
}  // namespace security::binexport

int main(int argc, char* argv[]) {
  return security::binexport::InvokeMainAndReportErrors(
      security::binexport::FlowGraphMain, argc, argv);
}
