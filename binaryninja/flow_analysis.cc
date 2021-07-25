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

#include "third_party/zynamics/binexport/binaryninja/flow_analysis.h"

#include "base/logging.h"
#include "third_party/absl/strings/ascii.h"
#include "third_party/absl/strings/str_cat.h"
#include "third_party/absl/strings/str_format.h"
#include "third_party/zynamics/binexport/address_references.h"
#include "third_party/zynamics/binexport/flow_analysis.h"
#include "third_party/zynamics/binexport/util/format.h"
#include "third_party/zynamics/binexport/util/status_macros.h"
#include "third_party/zynamics/binexport/util/timer.h"
#include "third_party/zynamics/binexport/writer.h"
#include "third_party/zynamics/binexport/x86_nop.h"

namespace security::binexport {

int GetPermissions(BinaryNinja::BinaryView* view,
                   const BinaryNinja::Segment& segment) {
  int segment_flags = segment.GetFlags();
  int permissions = 0;
  if (segment_flags & SegmentDenyExecute) {
    permissions |= AddressSpace::kExecute;
  }
  if (segment_flags & SegmentWritable) {
    permissions |= AddressSpace::kWrite;
  }
  if (segment_flags & SegmentReadable) {
    permissions |= AddressSpace::kRead;
  }
  return permissions;
}

template <typename T>
T GetBytes(BinaryNinja::BinaryView* view, uint64_t start, size_t length) {
  BinaryNinja::DataBuffer buffer = view->ReadBuffer(start, length);
  const size_t bytes_read = buffer.GetLength();

  LOG_IF(ERROR, bytes_read != length) << absl::StrFormat(
      "Expected %d bytes at %08X, got %d", length, start, bytes_read);

  auto* data = reinterpret_cast<typename T::value_type*>(buffer.GetData());
  return T(data, data + bytes_read);
}

std::string GetBytes(BinaryNinja::BinaryView* view,
                     const Instruction& instruction) {
  return GetBytes<std::string>(view, instruction.GetAddress(),
                               instruction.GetSize());
}

std::vector<Byte> GetSegmentBytes(BinaryNinja::BinaryView* view, uint64_t start,
                                  size_t length) {
  return GetBytes<std::vector<Byte>>(view, start, length);
}

int GetArchitectureBitness(BinaryNinja::BinaryView* view) {
  return view->GetDefaultArchitecture()->GetAddressSize() * 8;
}

bool IsPossibleFunction(BinaryNinja::BinaryView* view, Address address) {
  return !view->GetBasicBlocksForAddress(address).empty();
}

std::string GetMnemonic(
    const std::vector<BinaryNinja::InstructionTextToken>& instruction_tokens) {
  for (const auto& token : instruction_tokens) {
    if (token.type == BNInstructionTextTokenType::InstructionToken) {
      return token.text;
    }
  }
  return "";
}

std::string ToString(BNInstructionTextTokenType type) {
  switch (type) {
    case TextToken:
      return "TextToken";
    case InstructionToken:
      return "InstructionToken";
    case OperandSeparatorToken:
      return "OperandSeparatorToken";
    case RegisterToken:
      return "RegisterToken";
    case IntegerToken:
      return "IntegerToken";
    case PossibleAddressToken:
      return "PossibleAddressToken";
    case BeginMemoryOperandToken:
      return "BeginMemoryOperandToken";
    case EndMemoryOperandToken:
      return "EndMemoryOperandToken";
    case FloatingPointToken:
      return "FloatingPointToken";
    case AnnotationToken:
      return "AnnotationToken";
    case CodeRelativeAddressToken:
      return "CodeRelativeAddressToken";
    case ArgumentNameToken:
      return "ArgumentNameToken";
    case HexDumpByteValueToken:
      return "HexDumpByteValueToken";
    case HexDumpSkippedByteToken:
      return "HexDumpSkippedByteToken";
    case HexDumpInvalidByteToken:
      return "HexDumpInvalidByteToken";
    case HexDumpTextToken:
      return "HexDumpTextToken";
    case OpcodeToken:
      return "OpcodeToken";
    case StringToken:
      return "StringToken";
    case CharacterConstantToken:
      return "CharacterConstantToken";
    case KeywordToken:
      return "KeywordToken";
    case TypeNameToken:
      return "TypeNameToken";
    case FieldNameToken:
      return "FieldNameToken";
    case NameSpaceToken:
      return "NameSpaceToken";
    case NameSpaceSeparatorToken:
      return "NameSpaceSeparatorToken";
    case TagToken:
      return "TagToken";
    case StructOffsetToken:
      return "StructOffsetToken";
    case StructOffsetByteValueToken:
      return "StructOffsetByteValueToken";
    case StructureHexDumpTextToken:
      return "StructureHexDumpTextToken";
    case GotoLabelToken:
      return "GotoLabelToken";
    case CommentToken:
      return "CommentToken";
    case PossibleValueToken:
      return "PossibleValueToken";
    case PossibleValueTypeToken:
      return "PossibleValueTypeToken";
    case ArrayIndexToken:
      return "ArrayIndexToken";
    case IndentationToken:
      return "IndentationToken";
    case CodeSymbolToken:
      return "CodeSymbolToken";
    case DataSymbolToken:
      return "DataSymbolToken";
    case LocalVariableToken:
      return "LocalVariableToken";
    case ImportToken:
      return "ImportToken";
    case AddressDisplayToken:
      return "AddressDisplayToken";
    case IndirectImportToken:
      return "IndirectImportToken";
    case ExternalSymbolToken:
      return "ExternalSymbolToken";
    default:
      return absl::StrCat("<invalid-", type, ">");
  }
}

Instruction ParseInstructionBinaryNinja(
    Address address, const BinaryNinja::InstructionInfo& instruction,
    const std::vector<BinaryNinja::InstructionTextToken>& instruction_tokens,
    CallGraph* call_graph, FlowGraph* flow_graph) {
  // TODO(cblichmann): Return if no code at address

  std::string mnemonic;
  enum {
    kStart,
    kMnemonic,
    kBeginOperand,
    kEndOperand,
    kError,
    kSuccess,
  } state = kStart;
  Operands operands;
  Expressions expressions;
  auto token = instruction_tokens.begin();
  const auto end = instruction_tokens.end();
  while (true) {
    switch (state) {
      case kStart:
        if (token->type != BNInstructionTextTokenType::InstructionToken) {
          LOG(ERROR) << "expected InstructionToken, found: "
                     << ToString(token->type);
          state = kError;
        } else {
          mnemonic = absl::StripAsciiWhitespace(token->text);
          state = kMnemonic;
          ++token;
        }
        break;
      case kMnemonic:
        while (token != end) {
          if (token->type != BNInstructionTextTokenType::TextToken) {
            state = kBeginOperand;
            break;
          }
          if (!absl::StripAsciiWhitespace(token->text).empty()) {
            LOG(ERROR) << "expected empty TextToken, got: \"" << token->text
                       << "\"";
            state = kError;
            break;
          }
          ++token;
        }
        break;
      case kBeginOperand:
        expressions.clear();
        while (token != end) {
          if (token->type ==
              BNInstructionTextTokenType::OperandSeparatorToken) {
            break;
          }
          expressions.push_back(Expression::Create(
              nullptr, std::string(absl::StripAsciiWhitespace(token->text)), 0,
              Expression::TYPE_SYMBOL));
          ++token;
        }
        if (!expressions.empty()) {
          state = kEndOperand;
        }
        break;
      case kEndOperand:
        operands.push_back(Operand::CreateOperand(expressions));
        ++token;
        state = token != end ? kBeginOperand : kSuccess;
        break;
      case kError:
        return Instruction(address);
      case kSuccess:
        // TODO(cblichmann): Set next_instruction = 0 on no flow.
        const Address next_instruction = address + instruction.length;
        return Instruction(address, next_instruction, instruction.length,
                           mnemonic, operands);
    }
  }

  // // TODO(cblichmann): Is this always the case in Binja? I.e. check for flow.
  // const Address next_instruction = address + instruction.length;
  //
  // // TODO(cblichmann): Create expression trees for operands
  // std::string operand;
  // std::string operand2;
  // const size_t num_tokens = instruction_tokens.size();
  // for (int i = 1; i < num_tokens; ++i) {
  //   const auto& token = instruction_tokens[i];
  //   absl::StrAppend(&operand, token.text);
  //   absl::StrAppend(&operand2, "|", token.text, "=", token.type);
  // }
  // absl::StripAsciiWhitespace(&mnemonic);
  // absl::StripAsciiWhitespace(&operand);
  // LOG(INFO) << FormatAddress(address) << ": " << mnemonic << " " << operand2
  //           << "|";
  //
  // if (!operand.empty()) {
  //   expressions.push_back(
  //       Expression::Create(0, operand, 0, Expression::TYPE_SYMBOL, 0));
  //   operands.push_back(Operand::CreateOperand(expressions));
  // }
  // return Instruction(address, next_instruction, instruction.length, mnemonic,
  //                    operands);
}

void AnalyzeFlow(
    BinaryNinja::BinaryView* view,
    const BinaryNinja::InstructionInfo& binja_instruction,
    Instruction* instruction, FlowGraph* flow_graph, CallGraph* call_graph,
    AddressReferences* address_references,
    EntryPointManager* entry_point_manager /*, const ModuleMap& modules*/) {
  const Address address = instruction->GetAddress();
  bool has_flow = binja_instruction.branchCount == 0;
  bool handled = false;

  for (int i = 0; i < binja_instruction.branchCount; ++i) {
    const auto branch_target = binja_instruction.branchTarget[i];
    switch (binja_instruction.branchType[i]) {
      case BNBranchType::UnconditionalBranch:
        flow_graph->AddEdge(FlowGraphEdge(address, branch_target,
                                          FlowGraphEdge::TYPE_UNCONDITIONAL));
        address_references->emplace_back(
            address, GetSourceExpressionId(*instruction, branch_target),
            branch_target, TYPE_UNCONDITIONAL);
        entry_point_manager->Add(branch_target,
                                 EntryPoint::Source::JUMP_DIRECT);
        handled = true;
        break;
      case BNBranchType::CallDestination:
        if (IsPossibleFunction(view, branch_target /*, modules*/)) {
          call_graph->AddFunction(branch_target);
          call_graph->AddEdge(address, branch_target);
          entry_point_manager->Add(branch_target,
                                   EntryPoint::Source::CALL_TARGET);
        }
        instruction->SetFlag(FLAG_CALL, true);
        address_references->emplace_back(
            address, GetSourceExpressionId(*instruction, branch_target),
            branch_target, TYPE_CALL_DIRECT);
        has_flow = true;
        handled = true;
        break;
      case BNBranchType::TrueBranch:
        flow_graph->AddEdge(
            FlowGraphEdge(address, branch_target, FlowGraphEdge::TYPE_TRUE));
        address_references->emplace_back(
            address, GetSourceExpressionId(*instruction, branch_target),
            branch_target, TYPE_TRUE);
        entry_point_manager->Add(
            branch_target,
            EntryPoint::Source::JUMP_DIRECT);  // True is main branch
        handled = true;
        break;
      case BNBranchType::FalseBranch:
        flow_graph->AddEdge(
            FlowGraphEdge(address, branch_target, FlowGraphEdge::TYPE_FALSE));
        address_references->emplace_back(
            address, GetSourceExpressionId(*instruction, branch_target),
            branch_target, TYPE_FALSE);
        entry_point_manager->Add(
            branch_target,
            EntryPoint::Source::JUMP_DIRECT);  // True is main branch
        handled = true;
        break;
      default:
        break;
    }
  }

  if (has_flow) {
    // Regular code flow
    entry_point_manager->Add(instruction->GetNextInstruction(),
                             EntryPoint::Source::CODE_FLOW);
  }

  const std::vector<BinaryNinja::ReferenceSource> xrefs =
      view->GetCodeReferences(address);
  const std::vector<BinaryNinja::ReferenceSource> callers =
      view->GetCallers(address);
  const bool unconditional_jump = false;
  int num_out_edges =
      (unconditional_jump ? 1 : 0) + xrefs.size() + callers.size();

  if (num_out_edges > 1) {  // Switch jump table
    auto table_address = std::numeric_limits<Address>::max();
    for (const auto& xref : xrefs) {
      flow_graph->AddEdge(
          FlowGraphEdge(address, xref.addr, FlowGraphEdge::TYPE_SWITCH));
      address_references->emplace_back(
          address, GetSourceExpressionId(*instruction, xref.addr), xref.addr,
          AddressReferenceType::TYPE_SWITCH);
      entry_point_manager->Add(xref.addr, EntryPoint::Source::JUMP_TABLE);
      table_address = std::min(table_address, static_cast<Address>(xref.addr));
      handled = true;
    }
    // Add a data reference to first address in switch table
    address_references->emplace_back(
        address, GetSourceExpressionId(*instruction, table_address),
        table_address, AddressReferenceType::TYPE_DATA);
  }
  // TODO(cblichmann): Address references, indirect calls...
}

absl::Status AnalyzeFlowBinaryNinja(BinaryNinja::BinaryView* view,
                                    EntryPoints* entry_points, Writer* writer,
                                    detego::Instructions* instructions,
                                    FlowGraph* flow_graph,
                                    CallGraph* call_graph) {
  Timer<> timer;
  AddressReferences address_references;

  // Add initial entry points as functions.
  for (const auto& entry_point : *entry_points) {
    if ((entry_point.IsFunctionPrologue() || entry_point.IsExternal() ||
         entry_point.IsCallTarget())) {
      call_graph->AddFunction(entry_point.address_);
    }
  }

  AddressSpace address_space;
  AddressSpace flags;
  for (const auto& segment_ref : view->GetSegments()) {
    const uint64_t segment_start = segment_ref->GetStart();
    const size_t segment_length = segment_ref->GetLength();
    const int section_permissions = GetPermissions(view, *segment_ref);
    address_space.AddMemoryBlock(
        segment_start, GetSegmentBytes(view, segment_start, segment_length),
        section_permissions);
    flags.AddMemoryBlock(segment_start,
                         AddressSpace::MemoryBlock(segment_length),
                         section_permissions);
  }

  Instruction::SetBitness(GetArchitectureBitness(view));
  Instruction::SetGetBytesCallback([view](const Instruction& instruction) {
    return GetBytes(view, instruction);
  });
  Instruction::SetMemoryFlags(&flags);

  LOG(INFO) << "flow analysis";
  // TODO(cblichmann): Support binaries with mixed archs where this makes sense
  //                   (i.e. ARM/Thumb)
  auto default_arch = view->GetDefaultArchitecture();
  const size_t max_instr_len = default_arch->GetMaxInstructionLength();
  for (EntryPointManager entry_point_manager(entry_points, "flow analysis");
       !entry_points->empty();) {
    const Address address = entry_points->back().address_;
    entry_points->pop_back();

    if (!flags.IsValidAddress(address) || (flags[address] & FLAG_VISITED)) {
      continue;
    }
    flags[address] |= FLAG_VISITED;

    auto instr_bytes =
        GetBytes<std::vector<Byte>>(view, address, max_instr_len);
    BinaryNinja::InstructionInfo binja_instruction;
    if (instr_bytes.empty() ||
        !default_arch->GetInstructionInfo(&instr_bytes[0], address,
                                          max_instr_len, binja_instruction)) {
      continue;
    }

    std::vector<BinaryNinja::InstructionTextToken> binja_tokens;
    size_t instr_len = binja_instruction.length;
    if (!default_arch->GetInstructionText(&instr_bytes[0], address, instr_len,
                                          binja_tokens)) {
      continue;
    }

    Instruction new_instruction = ParseInstructionBinaryNinja(
        address, binja_instruction, binja_tokens, call_graph, flow_graph);
    if (new_instruction.HasFlag(FLAG_INVALID)) {
      continue;
    }
    AnalyzeFlow(view, binja_instruction, &new_instruction, flow_graph,
                call_graph, &address_references, &entry_point_manager);
    // call_graph->AddStringReference(address, GetStringReference(address));
    // GetComments(ida_instruction, &call_graph->GetComments());

    instructions->push_back(new_instruction);
  }

  LOG(INFO) << "sorting instructions";
  SortInstructions(instructions);

  LOG(INFO) << "reconstructing flow graphs";
  std::sort(address_references.begin(), address_references.end());
  // TODO(cblichmann): Remove duplicates if any.
  ReconstructFlowGraph(instructions, *flow_graph, call_graph);

  LOG(INFO) << "reconstructing functions";
  flow_graph->ReconstructFunctions(instructions, call_graph,
                                   FlowGraph::NoReturnHeuristic::kNone);

  // Must be called after ReconstructFunctions() since that may remove source
  // basic blocks for an edge.
  flow_graph->PruneFlowGraphEdges();

  // Note: PruneFlowGraphEdges might add comments to the callgraph so the
  // post processing must happen afterwards.
  call_graph->PostProcessComments();

  LOG(INFO) << "Binary Ninja specific post processing";
  for (const auto& [address, function] : flow_graph->GetFunctions()) {
    // Find function name
    auto bn_symbol_ref = view->GetSymbolByAddress(address);
    if (!bn_symbol_ref) {
      continue;
    }

    function->SetName(
        bn_symbol_ref->GetRawName(),
        BNRustSimplifyStrToStr(bn_symbol_ref->GetFullName().c_str()));
  }

  const auto processing_time = absl::Seconds(timer.elapsed());
  timer.restart();

  LOG(INFO) << "writing...";
  writer
      ->Write(*call_graph, *flow_graph, *instructions, address_references,
              address_space)
      .IgnoreError();

  Operand::EmptyCache();
  Expression::EmptyCache();

  const auto writing_time = absl::Seconds(timer.elapsed());
  LOG(INFO) << absl::StrCat(view->GetFile()->GetOriginalFilename(), ": ",
                            HumanReadableDuration(processing_time),
                            " processing, ",
                            HumanReadableDuration(writing_time), " writing");
  return absl::OkStatus();
}

}  // namespace security::binexport
