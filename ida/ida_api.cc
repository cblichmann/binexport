// Copyright 2011-2021 Google LLC. All Rights Reserved.
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

#include "third_party/zynamics/binexport/ida/ida_api.h"

#include "third_party/absl/container/node_hash_map.h"
#include "third_party/absl/functional/bind_front.h"//DBG
#include "third_party/absl/memory/memory.h"

// Silence some compiler warnings in IDA SDK headers
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wvarargs"
#elif __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wvarargs"
#elif _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4005)
#pragma warning(disable : 4244)
#pragma warning(disable : 4267)
#endif

// Now include the problematic header, end_idasdk.inc will clean up again.
#include <pro.h>  // NOLINT

#include <auto.hpp>     // NOLINT
#include <expr.hpp>     // NOLINT
#include <frame.hpp>    // NOLINT
#include <ida.hpp>      // NOLINT
#include <idp.hpp>      // NOLINT
#include <kernwin.hpp>  // NOLINT
#include <loader.hpp>   // NOLINT
#include <struct.hpp>   // NOLINT

namespace security::binexport {

bool IdaApi::add_idc_func(const IdaSdk::ext_idcfunc_t& idc_function) {
  return ::add_idc_func(::ext_idcfunc_t{
      .name = idc_function.name,
      .fptr = idc_function.fptr,
      .args = idc_function.args,
      //.defvals = idc_function.defvals,
      .ndefvals = idc_function.ndefvals,
      .flags = idc_function.flags,
  });
};

bool IdaApi::auto_wait() { return ::auto_wait(); }

IdaApi::ea_t IdaApi::calc_stkvar_struc_offset(IdaSdk::func_t function,
                                              IdaSdk::insn_t instruction,
                                              int operand_index) {
  return ::calc_stkvar_struc_offset(
      function.get<::func_t>(), *instruction.get<::insn_t>(), operand_index);
}

//////////////////////////////////

IdaSdk::ea_t IdaSdk::insn_t::ea() const {
  return static_cast<::insn_t*>(wrapped_)->ea;
}

const char* IdaApi::get_plugin_options(const char* plugin_name) {
  return ::get_plugin_options(plugin_name);
}

size_t IdaApi::get_fchunk_qty() { return ::get_fchunk_qty(); }

IdaApi::func_t IdaApi::getn_fchunk(int index) {
  return WrapIdaType<func_t>(::getn_fchunk(index));
}

IdaApi::func_t IdaApi::get_func(ea_t address) {
  return WrapIdaType<func_t>(::get_func(address));
}

IdaSdk::ea_t IdaApi::get_max_offset(IdaSdk::struc_t struct_) {
  return ::get_max_offset(struct_.get<::struc_t>());
}

IdaSdk::struc_t IdaApi::get_frame(IdaApi::func_t function) {
  return WrapIdaType<struc_t>(::get_frame(function.get<::func_t>()));
}

std::unique_ptr<IdaSdk::idc_value_t> IdaApi::make_idc_value_t() {
  class IdcValue : public IdaSdk::idc_value_t {
   public:
    char vtype() const override { return wrapped_.vtype; }

    sval_t num() const override { return wrapped_.num; }
    std::array<uint16_t, 6> e() override { return {}; }  // wrapped_.e; }
    void* obj() const override { return wrapped_.obj; }
    int funcidx() const override { return wrapped_.funcidx; }
    void* pvoid() const override { return wrapped_.pvoid; }
    int64_t i64() const override { return wrapped_.i64; }

    const char* c_str() const override { return wrapped_.c_str(); }

    ::idc_value_t wrapped_;
  };
  return absl::make_unique<IdcValue>();
}

std::unique_ptr<IdaSdk::xrefblk_t> IdaApi::make_xrefblk_t() {
  class Xrefblk : public IdaSdk::xrefblk_t {
   public:
    explicit Xrefblk(IdaApi* ida_api) : ida_api_(ida_api) {}

    ea_t from() const override { return wrapped_.from; }
    ea_t to() const override { return wrapped_.to; }
    bool iscode() const override { return wrapped_.iscode; }
    uint8_t type() const override { return wrapped_.type; }
    bool user() const override { return wrapped_.user; }

    bool first_from(ea_t from, int flags) override {
      return wrapped_.first_from(from, flags);
    }
    bool next_from() override { return wrapped_.next_from(); }
    bool first_to(ea_t to, int flags) override {
      return wrapped_.first_to(to, flags);
    }
    bool next_to() override { return wrapped_.next_to(); }
    bool next_from(ea_t from, ea_t to, int flags) override {
      return wrapped_.next_from(from, to, flags);
    }
    bool next_to(ea_t from, ea_t to, int flags) override {
      return wrapped_.next_to(from, to, flags);
    }

    IdaApi* ida_api_;
    ::xrefblk_t wrapped_;
  };
  return absl::make_unique<Xrefblk>(this);
}

//////////////////////////////////////////////////////////////////////////////
static auto* g_ida_api = new IdaApi();

}  // namespace security::binexport