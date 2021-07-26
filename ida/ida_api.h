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

#ifndef IDA_IDA_API_H_
#define IDA_IDA_API_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>

namespace security::binexport {

class IdaSdk {
 protected:
  // Base class for value types that wrap native IDA API types.
  class BasicIdaTypeWrapper {
   public:
    BasicIdaTypeWrapper() = default;
    explicit BasicIdaTypeWrapper(void* wrapped) : wrapped_(wrapped) {}

    BasicIdaTypeWrapper(const BasicIdaTypeWrapper&) = default;
    BasicIdaTypeWrapper& operator=(const BasicIdaTypeWrapper&) = default;
    BasicIdaTypeWrapper(BasicIdaTypeWrapper&&) = default;
    BasicIdaTypeWrapper& operator=(BasicIdaTypeWrapper&&) = default;

    // Returns the wrapped IDA API object.
    template <typename T>
    T* get() const {
      return static_cast<T*>(wrapped_);
    }

    operator bool() const { return wrapped_ != nullptr; }
    bool operator==(const BasicIdaTypeWrapper& other) const {
      return wrapped_ == other.wrapped_;
    }
    bool operator!=(const BasicIdaTypeWrapper& other) const {
      return !(*this == other);
    }

   protected:
    void* wrapped_ = nullptr;
  };

  template <typename T, typename IdaT>
  T WrapIdaType(IdaT* wrapped) {
    return T(static_cast<void*>(wrapped));
  }

 public:
#ifdef __EA64__
  using adiff_t = int64_t;
  using asize_t = uint64_t;
  using ea_t = uint64_t;
  using sel_t = uint64_t;
#else
  using adiff_t = int32_t;
  using asize_t = uint32_t;
  using ea_t = uint32_t;
  using sel_t = uint32_t;
#endif
  using sval_t = adiff_t;
  using error_t = int;

  // Type used for IDC function arguments and return values. Use
  // IdaSdk::make_idc_value_t() to obtain an implementation.
  class idc_value_t {
   public:
    virtual ~idc_value_t() = default;

    virtual char vtype() const = 0;

    virtual sval_t num() const = 0;
    virtual std::array<uint16_t, 6> e() = 0;
    virtual void* obj() const = 0;
    virtual int funcidx() const = 0;
    virtual void* pvoid() const = 0;
    virtual int64_t i64() const = 0;

    virtual const char* c_str() const = 0;
  };

  using idc_func_t = error_t(idc_value_t* arguments, idc_value_t* return_value);

  struct ext_idcfunc_t {
    const char* name = nullptr;
    idc_func_t* fptr = nullptr;
    const char* args = nullptr;
    const idc_value_t* defvals = nullptr;
    int ndefvals = 0;
    int flags = 0;
  };
  /////////////////
  class func_t : public BasicIdaTypeWrapper {
   public:
    using BasicIdaTypeWrapper::BasicIdaTypeWrapper;
  };

  class insn_t : public BasicIdaTypeWrapper {
   public:
    using BasicIdaTypeWrapper::BasicIdaTypeWrapper;

    ea_t ea() const;
  };

  class struc_t : public BasicIdaTypeWrapper {
   public:
    using BasicIdaTypeWrapper::BasicIdaTypeWrapper;
  };

  // Structure to enumerate all cross references. Use IdaSdk::make_xrefblk_t()
  // to obtain an implementation.
  class xrefblk_t {
   public:
    virtual ~xrefblk_t() = default;

    virtual ea_t from() const = 0;
    virtual ea_t to() const = 0;
    virtual bool iscode() const = 0;
    virtual uint8_t type() const = 0;
    virtual bool user() const = 0;

    virtual bool first_from(ea_t from, int flags) = 0;
    virtual bool next_from() = 0;
    virtual bool first_to(ea_t to, int flags) = 0;
    virtual bool next_to() = 0;
    virtual bool next_from(ea_t from, ea_t to, int flags) = 0;
    virtual bool next_to(ea_t from, ea_t to, int flags) = 0;
  };

  static constexpr error_t eExecThrow = 90;
  static constexpr int EXTFUN_BASE = 0x01;
  static constexpr int EXTFUN_NORET = 0x02;
  static constexpr int EXTFUN_SAFE = 0x04;
  static constexpr int UA_MAXOP = 8;
  static constexpr int XREF_ALL = 0x00;
  static constexpr int XREF_FAR = 0x01;
  static constexpr int XREF_DATA = 0x02;

  virtual ~IdaSdk() = default;

  // Factory functions
  virtual std::unique_ptr<idc_value_t> make_idc_value_t() = 0;
  virtual std::unique_ptr<xrefblk_t> make_xrefblk_t() = 0;

  // Wrapped API functions
  virtual bool add_idc_func(const ext_idcfunc_t& func) = 0;
  virtual bool auto_wait() = 0;
  virtual ea_t calc_stkvar_struc_offset(func_t function, insn_t instruction,
                                        int operand_index) = 0;

  /*
  callui
  decode_insn
  enum_import_names
  find_regvar
  generate_disasm_line
  get_byte
  get_bytes
  get_cmt
  get_dword
  get_ea_name
  get_enum_id
  get_enum_name2
  get_extra_cmt
  get_fchunk_qty
  get_flags_ex
  get_frame
  get_func
  get_func_cmt
  get_import_module_name
  get_import_module_qty
  getinf
  getinf_buf
  getinf_flag
  get_max_strlit_length
  get_member
  get_member_name
  getn_fchunk
  getnseg
  get_path
  get_ph
  get_plugin_options
  get_reg_name
  getseg
  get_segm_qty
  get_spd
  get_sptr
  get_stkvar
  get_struc
  get_struc_name
  get_struc_size
  get_struct_operand
  hook_to_notification_point
  is_call_insn
  is_indirect_jump_insn
  is_loaded
  is_special_member
  is_stkvar
  netnode_supval
  netnode_valstr
  next_that
  ph
  print_insn_mnem
  qexit
  qfree
  qvector_reserve
  root_node
  segtype
  set_database_flag
  tag_remove
  unhook_from_notification_point
  xrefblk_t_first_from
  xrefblk_t_first_to
  xrefblk_t_next_from
  xrefblk_t_next_to
  */

  virtual const char* get_plugin_options(const char* plugin_name) = 0;
  virtual size_t get_fchunk_qty() = 0;
  virtual func_t getn_fchunk(int index) = 0;
  virtual func_t get_func(ea_t address) = 0;

  virtual struc_t get_frame(func_t function) = 0;

  virtual ea_t get_max_offset(struc_t struct_) = 0;

  struc_t get_frame(ea_t address) { return get_frame(get_func(address)); }
};

class IdaApi : public IdaSdk {
 public:
  bool add_idc_func(const ext_idcfunc_t& idc_function) override;
  bool auto_wait() override;
  ea_t calc_stkvar_struc_offset(func_t function, insn_t instruction,
                                int operand_index) override;
  const char* get_plugin_options(const char* plugin_name) override;
  size_t get_fchunk_qty() override;

  func_t getn_fchunk(int index) override;
  func_t get_func(ea_t address) override;
  struc_t get_frame(func_t function) override;
  ea_t get_max_offset(struc_t struct_) override;

  std::unique_ptr<idc_value_t> make_idc_value_t() override;
  std::unique_ptr<xrefblk_t> make_xrefblk_t() override;
};

}  // namespace security::binexport

#endif  // IDA_IDA_API_H_