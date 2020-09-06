# Copyright 2011-2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required(VERSION 3.14)
project(tools CXX)

# Utility library for implementing sub-commands
add_library(bxp_command_util
 command_util.h
 command_util.cc
 ../version.h
 ${CMAKE_CURRENT_BINARY_DIR}/../version.cc
)
add_library(bxp::command_util ALIAS bxp_command_util)
target_link_libraries(bxp_command_util PRIVATE
 absl::flags_parse
 absl::status
 absl::str_format
 binexport_base
)

# Entry point for BinExport command-line utilities.
add_executable(bxp bxp_main.cc)
target_link_libraries(bxp PRIVATE
  absl::flags_parse
  absl::status
  absl::str_format
  binexport_base
  binexport_shared
  bxp::command_util
)
install(TARGETS bxp RUNTIME DESTINATION binexport-prefix)

# Dummy command that does (mostly) nothing. Used for tests.
add_executable(bxp-dummy bxp_dummy.cc)
target_link_libraries(bxp-dummy PRIVATE
  absl::flags_parse
  absl::status
  absl::str_format
  binexport_base
  bxp::command_util
)
install(TARGETS binexport-dummy RUNTIME DESTINATION binexport-prefix)

if(BINEXPORT_ENABLE_DISASM)
  # Sub-command that disassembles a binary into BinExport format
  add_executable(bxp-disasm bxp_disasm.cc)
  target_include_directories(bxp-disasm PRIVATE
    ${zydis_INCLUDE_DIR}
  )
  target_link_directories(bxp-disasm PRIVATE
    ${zydis_LIB_DIR}
  )
  target_link_libraries(bxp-disasm PRIVATE
    absl::flags_parse
    absl::status
    absl::str_format
    binexport_base
    binexport_core
    binexport_shared
    bxp::command_util
    OpenSSL::SSL
    Zycore
    Zydis
  )
  install(TARGETS bxp-disasm RUNTIME DESTINATION binexport-prefix)
endif()

add_executable(binexport2dump binexport2dump.cc)
target_link_libraries(binexport2dump
  absl::flat_hash_map
  absl::hash
  absl::str_format
  absl::time
  binexport_base
  binexport_shared
)
install(TARGETS binexport2dump RUNTIME DESTINATION binexport-prefix)
