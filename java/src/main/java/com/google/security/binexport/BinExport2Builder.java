// Copyright 2019-2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.google.security.binexport;

import com.google.protobuf.ByteString;
import com.google.security.zynamics.BinExport.BinExport2;
import com.google.security.zynamics.BinExport.BinExport2.Builder;
import com.google.security.zynamics.BinExport.BinExport2.Comment.Type;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CodeUnitFormat;
import ghidra.program.model.listing.CodeUnitFormatOptions;
import ghidra.program.model.listing.CodeUnitIterator;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import java.io.File;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;
import java.util.TreeMap;
import java.util.function.ToIntFunction;

/**
 * Java implementation of the BinExport2 writer class for Ghidra using a builder
 * pattern.
 *
 * @author Christian Blichmann
 */
public class BinExport2Builder {
  private final Builder builder = BinExport2.newBuilder();

  private TaskMonitor monitor;

  private final Program program;
  private final AddressSetView addrSet;
  private final Listing listing;
  private final BasicBlockModel bbModel;

  private MnemonicMapper mnemonicMapper = new IdentityMnemonicMapper();
  private long addressOffset = 0;
  private boolean prependNamespace = false;

  public BinExport2Builder(Program ghidraProgram, AddressSetView ghidraAddrSet) {
    program = ghidraProgram;
    addrSet = ghidraAddrSet;
    listing = program.getListing();
    bbModel = new BasicBlockModel(program, true);
  }

  public BinExport2Builder setMnemonicMapper(MnemonicMapper mapper) {
    mnemonicMapper = mapper;
    return this;
  }

  public BinExport2Builder setAddressOffset(long offset) {
    addressOffset = offset;
    return this;
  }

  public BinExport2Builder setPrependNamespace(boolean isPrepended) {
    prependNamespace = isPrepended;
    return this;
  }

  private long getMappedAddress(Address address) {
    return address.getOffset() - addressOffset;
  }

  private long getMappedAddress(Instruction instr) {
    return getMappedAddress(instr.getAddress());
  }

  private void buildMetaInformation() {
    monitor.setIndeterminate(true);
    monitor.setMessage("Exporting meta data");

    // Ghidra uses a quad format like x86:LE:32:default, BinExport just keeps
    // the processor and address size.
    String[] quad = program.getLanguageID().toString().split(":", 4);
    // TODO(cblichmann): Canonicalize architecture names
    String arch = quad[0] + "-" + quad[2];

    builder.getMetaInformationBuilder()
        .setExecutableName(new File(program.getExecutablePath()).getName())
        .setExecutableId(program.getExecutableSHA256())
        .setArchitectureName(arch)
        .setTimestamp(System.currentTimeMillis() / 1000);
  }

  private void buildExpressions(Map<String, Integer> expressionIndices) {
    var cuf = new CodeUnitFormat(new CodeUnitFormatOptions());
    int id = 0;
    for (Instruction instr : listing.getInstructions(true)) {
      for (int i = 0; i < instr.getNumOperands(); i++) {
        String opRep = cuf.getOperandRepresentationString(instr, i);
        if (expressionIndices.putIfAbsent(opRep, id) != null) {
          continue;
        }
        id++;
        builder.addExpressionBuilder()
            .setType(BinExport2.Expression.Type.SYMBOL).setSymbol(opRep);
      }
    }
  }

  private void buildOperands(Map<String, Integer> expressionIndices) {
    var entries = new ArrayList<>(expressionIndices.entrySet());
    entries.sort(Entry.comparingByValue());
    for (var entry : entries) {
      builder.addOperandBuilder().addExpressionIndex(entry.getValue());
    }
  }

  private void buildMnemonics(Map<String, Integer> mnemonicIndices) {
    monitor.setIndeterminate(true);
    monitor.setMessage("Computing mnemonic histogram");
    var mnemonicHist = new HashMap<String, Integer>();
    for (Instruction instr : listing.getInstructions(true)) {
      mnemonicHist.merge(mnemonicMapper.getInstructionMnemonic(instr), 1,
          Integer::sum);
    }
    var mnemonicList = new ArrayList<>(mnemonicHist.entrySet());
    mnemonicList.sort(Comparator
        .comparingInt((ToIntFunction<Entry<String, Integer>>) Entry::getValue)
        .reversed().thenComparing(Entry::getKey));
    int id = 0;
    for (var entry : mnemonicList) {
      builder.addMnemonicBuilder().setName(entry.getKey());
      mnemonicIndices.put(entry.getKey(), id++);
    }
  }

  private void buildInstructions(Map<String, Integer> mnemonics,
      Map<String, Integer> expressionIndices,
      Map<Long, Integer> instructionIndices) {
    monitor.setIndeterminate(false);
    monitor.setMessage("Exporting instructions");
    monitor.setMaximum(listing.getNumInstructions());
    int progress = 0;
    Instruction prevInstr = null;
    long prevAddress = 0;
    int prevSize = 0;
    int id = 0;
    var cuf = new CodeUnitFormat(new CodeUnitFormatOptions());
    for (Instruction instr : listing.getInstructions(true)) {
      long address = getMappedAddress(instr);

      var instrBuilder = builder.addInstructionBuilder();
      // Write the full instruction address iff:
      // - there is no previous instruction
      // - the previous instruction doesn't have code flow into the current one
      // - the previous instruction overlaps the current one
      // - the current instruction is a function entry point
      if (prevInstr == null || !prevInstr.hasFallthrough()
          || prevAddress + prevSize != address
          || listing.getFunctionAt(instr.getAddress()) != null) {
        instrBuilder.setAddress(address);
      }
      try {
        var bytes = instr.getBytes();
        instrBuilder.setRawBytes(ByteString.copyFrom(bytes));
        prevSize = bytes.length;
      } catch (MemoryAccessException e) {
        // Leave raw bytes empty
      }
      int mnemonicIndex =
          mnemonics.get(mnemonicMapper.getInstructionMnemonic(instr));
      if (mnemonicIndex != 0) {
        // Only store if different from default value
        instrBuilder.setMnemonicIndex(mnemonicIndex);
      }
      instructionIndices.put(address, id++);

      // TODO(cblichmann): One expression per operand for now
      for (int i = 0; i < instr.getNumOperands(); i++) {
        var lookup =
            expressionIndices.get(cuf.getOperandRepresentationString(instr, i));
        if (lookup == null) {
          continue;
        }
        instrBuilder.addOperandIndex(lookup);
      }

      // Export call targets.
      for (Reference ref : instr.getReferenceIteratorTo()) {
        RefType refType = ref.getReferenceType();
        if (!refType.isCall()) {
          continue;
        }
        instrBuilder.addCallTarget(getMappedAddress(ref.getToAddress()));
      }

      prevInstr = instr;
      prevAddress = address;
      monitor.setProgress(progress++);
    }
  }

  private void buildBasicBlocks(Map<Long, Integer> instructionIndices,
      Map<Long, Integer> basicBlockIndices) throws CancelledException {
    int id = 0;
    for (var bbIter = bbModel.getCodeBlocks(monitor); bbIter.hasNext(); ) {
      CodeBlock bb = bbIter.next();

      var protoBb = builder.addBasicBlockBuilder();

      int instructionIndex;
      int beginIndex = -1;
      int endIndex = -1;
      for (Instruction instr : listing.getInstructions(bb, true)) {
        instructionIndex = instructionIndices.get(getMappedAddress(instr));
        if (beginIndex < 0) {
          beginIndex = instructionIndex;
          endIndex = beginIndex + 1;
        } else if (instructionIndex != endIndex) {
          // Sequence is broken, store an interval
          var indexRange = protoBb.addInstructionIndexBuilder().setBeginIndex(beginIndex);
          if (endIndex != beginIndex + 1) {
            // Omit end index in the single instruction interval case
            indexRange.setEndIndex(endIndex);
          }
          beginIndex = instructionIndex;
          endIndex = beginIndex + 1;
        } else {
          // Sequence is unbroken, remember endIndex
          endIndex = instructionIndex + 1;
        }
      }
      var indexRange = protoBb.addInstructionIndexBuilder().setBeginIndex(beginIndex);
      if (endIndex != beginIndex + 1) {
        // Like above, omit end index in the single instruction interval case
        indexRange.setEndIndex(endIndex);
      }
      basicBlockIndices.put(getMappedAddress(bb.getFirstStartAddress()), id++);
    }
  }

  private void buildFlowGraphs(Map<Long, Integer> basicBlockIndices)
      throws CancelledException {
    FunctionManager funcManager = program.getFunctionManager();
    monitor.setIndeterminate(false);
    monitor.setMaximum(funcManager.getFunctionCount());
    int i = 0;

    for (Function func : funcManager.getFunctions(true)) {
      monitor.setProgress(i++);
      if (func.getEntryPoint().isNonLoadedMemoryAddress()) {
        continue;
      }

      var bbIter = bbModel.getCodeBlocksContaining(func.getBody(), monitor);
      if (!bbIter.hasNext()) {
        continue; // Skip empty flow graphs, they only exist as call graph nodes
      }
      var flowGraph = builder.addFlowGraphBuilder();
      while (bbIter.hasNext()) {
        CodeBlock bb = bbIter.next();
        long bbAddress = getMappedAddress(bb.getFirstStartAddress());
        int id = basicBlockIndices.get(bbAddress);
        if (bbAddress == getMappedAddress(func.getEntryPoint())) {
          flowGraph.setEntryBasicBlockIndex(id);
        }
        flowGraph.addBasicBlockIndex(id);

        long bbLastInstrAddress =
            getMappedAddress(listing.getInstructionBefore(bb.getMaxAddress()));
        var edges = new ArrayList<BinExport2.FlowGraph.Edge>();
        var lastFlow = RefType.INVALID;
        for (var bbDestIter = bb.getDestinations(monitor); bbDestIter.hasNext(); ) {
          CodeBlockReference bbRef = bbDestIter.next();
          // BinExport2 only stores flow from the very last instruction of a
          // basic block.
          if (getMappedAddress(bbRef.getReferent()) != bbLastInstrAddress) {
            continue;
          }

          var edge = BinExport2.FlowGraph.Edge.newBuilder();
          var targetId = basicBlockIndices.get(getMappedAddress(bbRef.getDestinationAddress()));
          FlowType flow = bbRef.getFlowType();
          if (flow.isConditional() || lastFlow.isConditional()) {
            edge.setType(flow.isConditional()
                ? BinExport2.FlowGraph.Edge.Type.CONDITION_TRUE
                : BinExport2.FlowGraph.Edge.Type.CONDITION_FALSE);
            edge.setSourceBasicBlockIndex(id);
            if (targetId != null) {
              edge.setTargetBasicBlockIndex(targetId);
            }
            edges.add(edge.build());
          } else if (flow.isUnConditional() && !flow.isComputed()) {
            edge.setSourceBasicBlockIndex(id);
            if (targetId != null) {
              edge.setTargetBasicBlockIndex(targetId);
            }
            edges.add(edge.build());
          } else if (flow.isJump() && flow.isComputed()) {
            edge.setSourceBasicBlockIndex(id);
            if (targetId != null) {
              edge.setTargetBasicBlockIndex(targetId);
              edge.setType(BinExport2.FlowGraph.Edge.Type.SWITCH);
            }
            edges.add(edge.build());
          }
          lastFlow = flow;
        }
        flowGraph.addAllEdge(edges);
      }
      assert flowGraph.getEntryBasicBlockIndex() > 0;
    }
  }
  
  private void buildCallGraph() throws CancelledException {
    var callGraph = builder.getCallGraphBuilder();
    FunctionManager funcManager = program.getFunctionManager();
    monitor.setIndeterminate(false);
    monitor.setMaximum(funcManager.getFunctionCount() * 2L);
    int i = 0;
    int id = 0;
    Map<Long, Integer> vertexIndices = new HashMap<>();

    // First round, gather vertex indices for all functions.
    // TODO(cblichmann): Handle imports using getExternalFunctions()
    for (Function func : funcManager.getFunctions(true)) {
      monitor.setProgress(i++);
      Address entryPoint = func.getEntryPoint();
      if (entryPoint.isNonLoadedMemoryAddress()) {
        continue;
      }
      long mappedEntryPoint = getMappedAddress(entryPoint);

      var vertex = callGraph.addVertexBuilder().setAddress(mappedEntryPoint);
      if (func.isThunk()) {
        // Only store type if different from default value (NORMAL)
        vertex.setType(BinExport2.CallGraph.Vertex.Type.THUNK);
      }

      if (!func.getName().equals(SymbolUtilities.getDefaultFunctionName(entryPoint))) {
        // Ghidra does not seem to provide both mangled and demangled names
        // (like IDA). Once the Demangle analyzer or DemangleAllScript has run,
        // function names will always appear demangled. Short of running the
        // demangler ourselves and comparing before/after names, there is no way
        // to distinguish mangled from demangled names.
        // Hence, the BinExport will have the names in the mangle_name field.

        // Mangled name is the default, optionally prefixed with namespace.
        vertex.setMangledName(getFunctionName(func));
      }
      vertexIndices.put(mappedEntryPoint, id++);
    }

    // Second round, insert all call graph edges.
    for (Function func : funcManager.getFunctions(true)) {
      monitor.setProgress(i++);
      Address entryPoint = func.getEntryPoint();
      if (entryPoint.isNonLoadedMemoryAddress()) {
        continue;
      }

      var bbIter = bbModel.getCodeBlocksContaining(func.getBody(), monitor);
      if (!bbIter.hasNext()) {
        continue; // Skip empty flow graphs, they only exist as call graph nodes
      }
      id = vertexIndices.get(getMappedAddress(func.getEntryPoint()));

      while (bbIter.hasNext()) {
        CodeBlock bb = bbIter.next();

        for (var bbDestIter = bb.getDestinations(monitor); bbDestIter.hasNext(); ) {
          CodeBlockReference bbRef = bbDestIter.next();
          FlowType flow = bbRef.getFlowType();
          if (!flow.isCall()) {
            continue;
          }

          var targetId = vertexIndices.get(getMappedAddress(bbRef.getDestinationAddress()));
          if (targetId != null) {
            callGraph.addEdgeBuilder().setSourceVertexIndex(id).setTargetVertexIndex(targetId);
          }
        }
      }
    }
  }

  private void buildStrings(Map<Long, Integer> instructionIndices) {
    monitor.setMessage("Exporting strings");
    monitor.setIndeterminate(true);
    Data data;
    String type;
    var strToInstr = new ArrayList<Map.Entry<Integer, Integer>>();
    for (DataIterator dataIt = listing.getDefinedData(true);
        dataIt.hasNext() && !monitor.isCancelled(); ) {
      data = dataIt.next();
      type = data.getDataType().getName().toLowerCase(Locale.ROOT);
      if ((!type.contains("unicode") && !type.contains("string")) || data.isEmpty()) {
        continue;
      }
      builder.addStringTable(data.getDefaultValueRepresentation());
      int strIdx = builder.getStringTableCount();

      long address = getMappedAddress(data.getAddress());
      Integer instrIdx = instructionIndices.get(address);
      if (instrIdx == null) {
        continue;
      }
      strToInstr.add(Map.entry(strIdx, instrIdx));
    }
    for (var entry : strToInstr) {
      builder.addStringReferenceBuilder()
          .setInstructionIndex(entry.getValue())
          .setStringTableIndex(entry.getKey());
    }
  }

  private void buildComments(Map<Long, Integer> instructionIndices) {
    monitor.setMessage("Exporting comments");
    monitor.setIndeterminate(true);
    for (int commentType : List.of(CodeUnit.EOL_COMMENT)) {
      for (CodeUnitIterator codeIt = listing.getCommentCodeUnitIterator(commentType, addrSet);
          codeIt.hasNext() && !monitor.isCancelled(); ) {
        CodeUnit code = codeIt.next();
        long address = getMappedAddress(code.getMinAddress());
        Integer instrIdx = instructionIndices.get(address);
        if (instrIdx == null) {
          continue;
        }

        // TODO(cblichmann): Deduplicate!
        builder.addStringTable(code.getComment(commentType));
        int strIdx = builder.getStringTableCount();

        builder.addCommentBuilder()
            .setInstructionIndex(instrIdx)
            .setStringTableIndex(strIdx)
            .setRepeatable(false)
            .setType(Type.DEFAULT)
        ;
        int commentIdx = builder.getCommentCount();

        builder.getInstructionBuilder(instrIdx)
            .addCommentIndex(commentIdx);
      }
    }
  }

  private void buildSections() {
    monitor.setMessage("Exporting sections");
    monitor.setIndeterminate(false);
    MemoryBlock[] blocks = program.getMemory().getBlocks();
    monitor.setMaximum(blocks.length);
    for (int i = 0; i < blocks.length; i++) {
      var block = blocks[i];
      builder.addSectionBuilder().setAddress(block.getStart().getOffset())
          .setSize(block.getSize()).setFlagR(block.isRead())
          .setFlagW(block.isWrite()).setFlagX(block.isExecute());
      monitor.setProgress(i);
    }
  }

  /**
   * Parses a Ghidra instruction and outputs its components on stdout.
   * Experimental.
   *
   * @param instr the instruction to parse.
   */
  @SuppressWarnings("unused")
  private void parseInstruction(Instruction instr) {
    if (instr.getAddress().getOffset() != 0x1420) {
      return;
    }

    var funMgr = program.getFunctionManager();
    var refMgr = program.getReferenceManager();

    System.out.printf("%08X: %s (%s) ops:#%d{\n",
        instr.getAddress().getOffset(), instr.getMnemonicString(),
        instr.getLabel(), instr.getNumOperands());

    Function fun = funMgr.getFunctionContaining(instr.getAddress());
    var params =
        fun.getParameters(
            variable -> {
              var p = (Parameter) variable;
              Address addr = fun.getEntryPoint().add(p.getFirstUseOffset());
              System.out.printf(
                  "P: %s, %d, %08X %s\n",
                  p.getName(), p.getFirstUseOffset(), addr.getOffset(), p.getRegister());

              return instr.getAddress().equals(addr);
            });
    var cuf = new CodeUnitFormat(new CodeUnitFormatOptions());

    for (int i = 0; i < instr.getNumOperands(); i++) {
      Symbol[] syms = instr.getSymbols();

      System.out.printf("  sym:#%d[\n", syms.length);
      for (final var sym : syms) {
        System.out.printf("    \"%s\"", sym.toString());
      }
      System.out.print("  ]\n");

      Reference[] refs = instr.getOperandReferences(i);
      System.out.printf("  ref:#%d[\n", refs.length);
      for (var ref : refs) {
        var var = refMgr.getReferencedVariable(ref);
        System.out.printf("    \"%s\"", ref.toString());
        if (var != null) {
          System.out.printf(" (%s) @%s", var.getName(), var.getMinAddress().toString());
        }
        System.out.print("\n");
      }
      System.out.print("  ]\n");

      Object[] objs = instr.getOpObjects(i);
      System.out.printf("  obj:#%d[\n", objs.length);
      for (var obj : objs) {
        System.out.printf("    %s: \"%s\"", obj.getClass().getName(), obj);
        if (obj instanceof Register) {
          var reg = (Register) obj;
        } else if (obj instanceof Scalar) {
          var scalar = (Scalar) obj;
        }
        System.out.print("\n");
      }
      System.out.print("  ]\n");
      System.out.print(",\n");
    }
    System.out.print("}\n");
    throw new RuntimeException();
  }

  private String getFunctionName(Function function) {
    if (!prependNamespace) {
      return function.getName();
    }
    // Push all parent namespace names on top of the Vector.
    var functionNameComponents = new ArrayList<String>();
    var parentNamespace = function.getParentNamespace();
    while (parentNamespace != null && !"Global".equals(parentNamespace.getName())) {
      functionNameComponents.add(0, parentNamespace.getName());
      parentNamespace = parentNamespace.getParentNamespace();
    }
    // Add the name of the function as the last component.
    functionNameComponents.add(function.getName());
    return String.join("::", functionNameComponents);
  }

  public BinExport2 build(TaskMonitor taskMonitor) throws CancelledException {
    monitor = taskMonitor != null ? taskMonitor : TaskMonitor.DUMMY;

    buildMetaInformation();

    // TODO(cblichmann): Implement full expression trees. For now, each
    //                   expression corresponds to exactly one operand. Those
    //                   consist of Ghidra's string representation and are of
    //                   type SYMBOL.
    var expressionIndices = new HashMap<String, Integer>();
    buildExpressions(expressionIndices);
    buildOperands(expressionIndices);

    var mnemonics = new TreeMap<String, Integer>();
    buildMnemonics(mnemonics);
    var instructionIndices = new TreeMap<Long, Integer>();
    buildInstructions(mnemonics, expressionIndices, instructionIndices);
    monitor.setMessage("Exporting basic block structure");
    var basicBlockIndices = new HashMap<Long, Integer>();
    buildBasicBlocks(instructionIndices, basicBlockIndices);
    buildComments(instructionIndices);
    buildStrings(instructionIndices);
    // TODO(cblichmann): Implement buildDataReferences()
    monitor.setMessage("Exporting flow graphs");
    buildFlowGraphs(basicBlockIndices);
    monitor.setMessage("Exporting call graph");
    buildCallGraph();
    buildSections();

    return builder.build();
  }

  public BinExport2 build() {
    try {
      return build(TaskMonitor.DUMMY);
    } catch (final CancelledException e) {
      assert false : "TaskMonitor.DUMMY should not throw";
      throw new RuntimeException(e);
    }
  }
}
