/////////////////////////////////////////////////////////////////////////
//
// Author: Mateusz Jurczyk (mjurczyk@google.com)
//
// Copyright 2017-2018 Google LLC
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
//

#include <stdint.h>
#include <stdarg.h>
#include <string>
#include <vector>
#include <windows.h>

#include "bochs.h"
#include "cpu/cpu.h"
#include "disasm/disasm.h"

#include "breakpoints.h"
#include "common.h"
#include "instrument.h"
#include "logging.pb.h"
#include "os_windows.h"
#include "symbols.h"
#include "taint.h"


// ------------------------------------------------------------------
// Helper functions' implementation.
// ------------------------------------------------------------------

static void set_breakpoints_bulk(const std::vector<uint32_t>& addresses, int type) {
  for (uint32_t address : addresses) {
    bp::add_breakpoint(address, type);
  }
}

static void parse_offset_list(char *buffer, std::vector<uint32_t> *v) {
  char *pch = strtok(buffer, ",");
  while (pch != NULL) {
    uint32_t address = strtoul(pch, NULL, 16);
    v->push_back(address);

    pch = strtok(NULL, ",");
  }
}

static bool init_basic_config(const char *config_path, bochspwn_config *config) {
  static char buffer[256];

  // Output file path.
  READ_INI_STRING(config_path, "general", "log_path", buffer, sizeof(buffer));
  config->log_path = strdup(buffer);

  // System version.
  READ_INI_STRING(config_path, "general", "version", buffer, sizeof(buffer));
  config->os_version = strdup(buffer);

  // Maximum length of callstack.
  READ_INI_INT(config_path, "general", "callstack_length", buffer, sizeof(buffer),
               &config->callstack_length);

  // Symbolization settings.
  READ_INI_INT(config_path, "general", "symbolize", buffer, sizeof(buffer),
               &config->symbolize);
  READ_INI_STRING(config_path, "general", "symbol_path", buffer, sizeof(buffer));
  config->symbol_path = strdup(buffer);

  // Read the pools-tainting setting.
  READ_INI_INT(config_path, "general", "taint_pools", buffer, sizeof(buffer),
               &config->taint_pools);

  // Read the stack-tainting setting.
  READ_INI_INT(config_path, "general", "taint_stack", buffer, sizeof(buffer),
               &config->taint_stack);

  // Read the origin tracking setting.
  READ_INI_INT(config_path, "general", "track_origins", buffer, sizeof(buffer),
               &config->track_origins);

  // Comma-separated list of pool allocation routine offsets.
  std::vector<uint32_t> pool_allocs;
  READ_INI_STRING(config_path, "general", "pool_allocs", buffer, sizeof(buffer));
  parse_offset_list(buffer, &pool_allocs);
  set_breakpoints_bulk(pool_allocs, BP_POOL_ALLOC);

  // Comma-separated list of pool deallocation routine offsets.
  std::vector<uint32_t> pool_frees;
  READ_INI_STRING(config_path, "general", "pool_frees", buffer, sizeof(buffer));
  parse_offset_list(buffer, &pool_frees);
  set_breakpoints_bulk(pool_frees, BP_POOL_FREE);

  // Read the uniquization setting.
  READ_INI_INT(config_path, "general", "uniquize", buffer, sizeof(buffer), &config->uniquize);

  // Read the break-on-bug setting.
  READ_INI_INT(config_path, "general", "break_on_bug", buffer, sizeof(buffer), &config->break_on_bug);

  // Read the only-kernel-to-user setting.
  READ_INI_INT(config_path, "general", "only_kernel_to_user", buffer, sizeof(buffer),
               &config->only_kernel_to_user);

  // Read the state-dumping settings.
  READ_INI_INT(config_path, "general", "dump_shadow_to_files", buffer, sizeof(buffer),
               &config->dump_shadow_to_files);
  
  if (config->dump_shadow_to_files != 0) {
    READ_INI_INT(config_path, "general", "dump_shadow_interval", buffer, sizeof(buffer),
                 &config->dump_shadow_interval);

    READ_INI_STRING(config_path, "general", "dump_shadow_path", buffer, sizeof(buffer));
    config->dump_shadow_path = strdup(buffer);
  }

  return true;
}

static std::string bug_report_as_text(const bug_report_t& bug_report) {
  char buffer[256];
  std::string ret;

  snprintf(buffer, sizeof(buffer),
           "[pid/tid: %.8x/%.8x] {%16s} %s of %llx "
           "(%u bytes, %s), pc = %llx [ %40s ]\n",
           bug_report.process_id(), bug_report.thread_id(),
           bug_report.image_file_name().c_str(),
           translate_mem_access(bug_report.access_type()),
           bug_report.lin(),
           (unsigned)bug_report.len(),
           bug_report.kernel_to_user() ? "kernel--->user" : "kernel--->kernel",
           bug_report.pc(),
           bug_report.pc_disasm().c_str());
  ret = buffer;

  if (bug_report.has_alloc_address() && bug_report.has_alloc_size() && bug_report.has_alloc_tag()) {
    snprintf(buffer, sizeof(buffer),
             "Allocation base=%x, size=%u (%x), tag=%x, offset=%x\n",
             bug_report.alloc_address(), bug_report.alloc_size(), bug_report.alloc_size(), bug_report.alloc_tag(),
             bug_report.lin() - bug_report.alloc_address());
  } else {
    snprintf(buffer, sizeof(buffer), "[Allocation not recognized]\n");
  }
  ret += buffer;

  if (bug_report.has_alloc_origin()) {
    snprintf(buffer, sizeof(buffer), "Allocation origin: %x\n", bug_report.alloc_origin());
    ret += buffer;
  }

  if (bug_report.has_copy_dest_address()) {
    snprintf(buffer, sizeof(buffer), "Destination address: %x\n", bug_report.copy_dest_address());
    ret += buffer;
  }

  ret += "Init: ";
  for (unsigned int i = 0; i < bug_report.meta_init().size(); i++) {
    snprintf(buffer, sizeof(buffer), "%.2x ", (uint8_t)bug_report.meta_init()[i]);
    ret += buffer;
  }

  ret += "Bytes: ";
  for (unsigned int i = 0; i < bug_report.region_body().size(); i++) {
    snprintf(buffer, sizeof(buffer), "%.2x ", (uint8_t)bug_report.region_body()[i]);
    ret += buffer;
  }
  ret += "\n";

  if (bug_report.kernel_to_user() && bug_report.has_full_copy_meta_init()) {
    ret += "Full copy init:\n";
    ret += format_hex(bug_report.full_copy_meta_init());
  }

  ret += "Stack trace:\n";
  for (int i = 0; i < bug_report.stack_trace_size(); i++) {
    if (globals::config.symbolize) {
      snprintf(buffer, sizeof(buffer), " #%u  0x%llx ((%.8llx) %s)\n", i,
               (bug_report.stack_trace(i).module_base() + bug_report.stack_trace(i).relative_pc()),
               bug_report.stack_trace(i).relative_pc(),
               symbols::symbolize(bug_report.stack_trace(i).module_name(),
                                  bug_report.stack_trace(i).relative_pc()).c_str());
    } else {
      snprintf(buffer, sizeof(buffer), " #%u  0x%llx (%s+%.8x)\n", i,
               (bug_report.stack_trace(i).module_base() + bug_report.stack_trace(i).relative_pc()),
               bug_report.stack_trace(i).module_name().c_str(),
               (unsigned)bug_report.stack_trace(i).relative_pc());
    }
    ret += buffer;
  }

  return ret;
}

__attribute__((noinline))
static void process_mem_access(BX_CPU_C *pcpu, bx_address lin, unsigned len,
                               bx_address pc, bug_report_t::mem_access_type access_type,
                               char *disasm, bool kernel_to_user, uint32_t copy_dest_address,
                               bool has_alloc_info, bx_address alloc_base, unsigned int alloc_size,
                               uint32_t alloc_tag, uint32_t alloc_origin, uint8_t *meta_init,
                               bool has_full_copy_meta_init, uint8_t *full_copy_meta_init,
                               uint8_t *body) {
  static bug_report_t bug_report;

  bug_report.Clear();
  bug_report.set_lin(lin);
  bug_report.set_len(len);
  bug_report.set_pc(pc);
  bug_report.set_access_type(access_type);
  bug_report.set_pc_disasm(disasm);
  bug_report.set_kernel_to_user(kernel_to_user);
  if (kernel_to_user) {
    bug_report.set_copy_dest_address(copy_dest_address);
  }
  if (has_alloc_info) {
    bug_report.set_alloc_address(alloc_base);
    bug_report.set_alloc_size(alloc_size);
    bug_report.set_alloc_tag(alloc_tag);
  }
  if (globals::config.track_origins) {
    bug_report.set_alloc_origin(alloc_origin);
  }
  bug_report.set_meta_init(meta_init, len);
  if (has_alloc_info && has_full_copy_meta_init) {
    bug_report.set_full_copy_meta_init(full_copy_meta_init, alloc_size);
  }
  bug_report.set_region_body(body, len);

  if (windows::fill_info(pcpu, &bug_report)) {
    bool new_item = false;

    if (globals::config.uniquize) {
      for (int i = 0; i < bug_report.stack_trace_size(); i++) {
        uint32_t callstack_addr = bug_report.stack_trace(i).module_base() +
                                  bug_report.stack_trace(i).relative_pc();

        if (globals::known_callstack_item.find(callstack_addr) == globals::known_callstack_item.end()) {
          new_item = true;
          globals::known_callstack_item.insert(callstack_addr);
        }
      }
    } else {
      new_item = true;
    }

    if (new_item) {
      FILE *f = globals::config.file_handle;

      fprintf(f, "\n------------------------------ found uninit-access of address %x\n\n", bug_report.lin());
      fprintf(f, "%s", bug_report_as_text(bug_report).c_str());
      fflush(f);

      // Generate an exception if requested by the user.
      if (globals::config.break_on_bug && kernel_to_user) {
        invoke_guest_int3(pcpu);
      }
    }
  }
}

static void destroy_globals() {
  for (unsigned int i = 0; i < globals::modules.size(); i++) {
    delete globals::modules[i];
  }
  globals::modules.clear();

  for (unsigned int i = 0; i < globals::special_modules.size(); i++) {
    delete globals::special_modules[i];
  }
  globals::special_modules.clear();

  globals::known_callstack_item.clear();
}

// ------------------------------------------------------------------
// Thread routine periodically saving the shadow memory state to disk.
// ------------------------------------------------------------------
DWORD WINAPI DumpShadowThreadRoutine(LPVOID lpParameter) {
  char buffer[MAX_PATH];
  for (int it = 0;; it++) {
    snprintf(buffer, sizeof(buffer), "%s/%.6d.raw", globals::config.dump_shadow_path, it);
    taint::dump_state(buffer);
    Sleep(globals::config.dump_shadow_interval * 1000);
  }

  return 0;
}

// ------------------------------------------------------------------
// Instrumentation implementation.
// ------------------------------------------------------------------

// Callback invoked on Bochs CPU initialization.
void bx_instr_initialize(unsigned cpu) {
  // Obtain configuration file path.
  char *conf_path = NULL;
  if (conf_path = getenv(kConfFileEnvVariable), conf_path == NULL) {
    fprintf(stderr, "Configuration file not specified in \"%s\"\n",
            kConfFileEnvVariable);
    abort();
  }

  // Read basic configuration from .ini file.
  if (!init_basic_config(conf_path, &globals::config)) {
    fprintf(stderr, "Initialization with config file \"%s\" failed\n", conf_path);
    abort();
  }

  // Initialize output file handle for the first time.
  globals::config.file_handle = fopen(globals::config.log_path, "wb");
  if (!globals::config.file_handle) {
    fprintf(stderr, "Unable to open the \"%s\" log file\n", globals::config.log_path);
    abort();
  }
  // Allow the guest-specific part to initialize (read internal offsets etc).
  if (!windows::init(conf_path)) {
    fprintf(stderr, "Guest-specific initialization with file \"%s\" failed\n", conf_path);
    abort();
  }

  // Initialize symbols subsystem.
  symbols::initialize();

  // Initialize the taint subsystem.
  taint::initialize(globals::config.track_origins != 0,
                    globals::config.dump_shadow_to_files != 0);

  // Initialize helper taint allocations.
  globals::pool_taint_alloc = (uint8_t *)malloc(kTaintHelperAllocSize);
  memset(globals::pool_taint_alloc, kPoolTaintByte, kTaintHelperAllocSize);

  globals::stack_taint_alloc = (uint8_t *)malloc(kTaintHelperAllocSize);
  memset(globals::stack_taint_alloc, kStackTaintByte, kTaintHelperAllocSize);

  // Start a thread to periodically dump the shadow memory, if needed.
  if (globals::config.dump_shadow_to_files != 0) {
    CreateThread(NULL, 0, DumpShadowThreadRoutine, NULL, 0, NULL);
  }
}

// Callback invoked on destroying a Bochs CPU object.
void bx_instr_exit(unsigned cpu) {
  // Free the symbols subsystem.
  symbols::destroy();

  // Free the taint subsystem.
  taint::destroy();

  // Free allocations in global structures.
  destroy_globals();

  // Free helper allocations.
  free(globals::pool_taint_alloc);
  globals::pool_taint_alloc = NULL;
  
  free(globals::stack_taint_alloc);
  globals::stack_taint_alloc = NULL;
}

// Callback invoked upon a CPU interrupt.
void bx_instr_interrupt(unsigned cpu, unsigned vector) {
  if (globals::bp_active && vector == 3) {
    BX_CPU_C *pcpu = BX_CPU(cpu);
    write_lin_mem(pcpu, globals::bp_address, 1, &globals::bp_orig_byte);

    globals::bp_active = false;
  }
}

// Callback called on attempt to access linear memory.
//
// Note: the BX_INSTR_LIN_ACCESS instrumentation doesn't work when
// repeat-speedups feature is enabled. Always remember to set
// BX_SUPPORT_REPEAT_SPEEDUPS to 0 in config.h, otherwise Bochspwn might
// not work correctly.
void bx_instr_lin_access(unsigned cpu, bx_address lin, bx_address phy,
                         unsigned len, unsigned memtype, unsigned rw) {
  BX_CPU_C *pcpu = BX_CPU(cpu);

  // Not going to use physical memory address.
  (void)phy;

  // Note: DO NOT change order of these ifs. long64_mode must be called
  // before protected_mode, since it will also return "true" on protected_mode
  // query (well, long mode is technically protected mode).
  if (pcpu->long64_mode()) {
    fprintf(stderr, "Instrumentation not supported in 64-bit mode. aborting\n");
    abort();
  } else if (!pcpu->protected_mode()) {
    // No other modes than protected mode are interesting.
    return;
  }

  bx_address pc = pcpu->prev_rip;
  if (!windows::check_kernel_addr(pc)) {
    return; /* pc not in ring-0 */
  }

  bool kernel_to_user = false;
  uint32_t copy_dest_address = 0;
  if (globals::rep_movs) {
    bool dst_in_kernel = windows::check_kernel_addr(pcpu->gen_reg[BX_32BIT_REG_EDI].rrx);
    bool src_in_kernel = windows::check_kernel_addr(pcpu->gen_reg[BX_32BIT_REG_ESI].rrx);

    // One of dst/src must be kernel-mode for it to be interesting.
    if (!dst_in_kernel && !src_in_kernel) {
      return;
    }

    // If this is a REP MOVSx, set taint if the source data is coming from
    // user-mode. Otherwise, let the "READ" part of the handler copy the
    // taint data from one allocation to another.
    if (rw == BX_WRITE) {
      if (dst_in_kernel && !src_in_kernel) {
        taint::set_init_type(lin, len, MEM_INIT);
      }
    } else {
      // For READ, either propatate the taint for bytes which are also
      // part of a pool allocation, or check taint if we're copying
      // back to user-mode.
      if (dst_in_kernel && src_in_kernel) {
        taint::copy_taint(pcpu->gen_reg[BX_32BIT_REG_EDI].rrx, lin, len);
        if (globals::config.track_origins) {
          taint::copy_origin(pcpu->gen_reg[BX_32BIT_REG_EDI].rrx, lin, len);
        }
      } else if (!dst_in_kernel && src_in_kernel) {
        taint::access_type ac_type = taint::check_access(pcpu, lin, len);
        if (ac_type == taint::ACCESS_INVALID) {
          kernel_to_user = true;
          copy_dest_address = pcpu->gen_reg[BX_32BIT_REG_EDI].rrx;
          goto error_found;
        } else if (ac_type == taint::METADATA_PADDING_MISMATCH) {
          taint::set_init_type(lin, len, MEM_INIT);
        }
      }
    }
    return;
  }

  // If not a REP MOVSx, check that the source is in kernel-mode.
  if (!windows::check_kernel_addr(lin)) {
    return;
  }

  // BX_RW is used for setting variables to zero in Windows, e.g.
  //
  // and [r32+imm32], 0
  //
  // While it's likely that there are other RW operations which re-use the
  // uninitialized value, a READ over the memory will be caught and reported
  // anyway.
  if (rw == BX_WRITE || rw == BX_RW) {
    taint::set_init_type(lin, len, MEM_INIT);
    return;
  } else {
    taint::access_type ac_type = taint::check_access(pcpu, lin, len);
    if (ac_type == taint::ACCESS_VALID) {
      return;
    } else if (ac_type == taint::METADATA_PADDING_MISMATCH) {
      taint::set_init_type(lin, len, MEM_INIT);
      return;
    } else {
      // The last case - taint::ACCESS_INVALID in handled further on in the
      // function.
    }
  }

error_found:
  // If an uninitialized read from kernel-mode memory was detected but we're
  // only interested in kernel--->user leaks, don't report the bug.
  if (globals::config.only_kernel_to_user && !kernel_to_user) {
    return;
  }

  // Save basic information about the access.
  bug_report_t::mem_access_type access_type;
  if (rw == BX_READ) {
    access_type = bug_report_t::MEM_READ;
  } else if (rw == BX_EXECUTE) {
    access_type = bug_report_t::MEM_EXEC;
  } else {
    abort();
  }

  // Disassemble current instruction.
  static Bit8u ibuf[32] = {0};
  static char pc_disasm[64];
  if (read_lin_mem(pcpu, pc, sizeof(ibuf), ibuf)) {
    disassembler bx_disassemble;
    bx_disassemble.disasm(true, false, 0, pc, ibuf, pc_disasm);
  }

  // With basic information filled in, process the access further.
  bx_address alloc_base = 0;
  unsigned int alloc_size = 0;
  uint32_t alloc_tag = 0;
  bool has_alloc_info = taint::get_alloc_info(lin, &alloc_base, &alloc_size, &alloc_tag);

  uint32_t alloc_origin = 0;
  if (globals::config.track_origins) {
    alloc_origin = taint::get_origin(lin);
  }

  static uint8_t meta_init[32];
  static uint8_t full_copy_meta_init[4096];
  static uint8_t body[32];

  taint::get_metadata(lin, len, meta_init);

  bool has_full_copy_meta_init = false;
  if (has_alloc_info && alloc_size <= sizeof(full_copy_meta_init)) {
    has_full_copy_meta_init = true;
    taint::get_metadata(alloc_base, alloc_size, full_copy_meta_init);
  }

  assert(read_lin_mem(pcpu, lin, len, body));

  process_mem_access(pcpu, lin, len, pc, access_type, pc_disasm, kernel_to_user, copy_dest_address,
                     has_alloc_info, alloc_base, alloc_size, alloc_tag, alloc_origin, meta_init,
                     has_full_copy_meta_init, full_copy_meta_init, body);
}

// Callback invoked before execution of each instruction takes place.
void bx_instr_before_execution(unsigned cpu, bxInstruction_c *i) {
  BX_CPU_C *pcpu = BX_CPU(cpu);
  bx_address pc = pcpu->prev_rip;

  // We're only really interested in protected mode, kernel-mode code.
  if (!pcpu->protected_mode() || !windows::check_kernel_addr(pc)) {
    return;
  }

  const unsigned int opcode = i->getIaOpcode();
  if (opcode == BX_IA_RET_Op32_Iw) /* Handling of RETn opcode (allocators) */ {
    if (globals::special_modules.empty()) {
      windows::update_module_list(pcpu, pc);

      if (!globals::special_modules.empty()) {
        globals::nt_base = globals::special_modules[0]->module_base;
      }
      return;
    }

    // Check if it's one of the pool allocation routines.
    const unsigned int kPageAllocBoundary = 4080;
    switch (bp::check_breakpoint(pc - globals::nt_base)) {
      case BP_POOL_ALLOC: {
        bx_address region = pcpu->gen_reg[BX_32BIT_REG_EAX].rrx;
        if (region != 0) {
          unsigned int len;
          uint32_t tag;

          if (read_lin_mem(pcpu, pcpu->gen_reg[BX_32BIT_REG_ESP].rrx + 2 * 4, 4, &len) &&
              read_lin_mem(pcpu, pcpu->gen_reg[BX_32BIT_REG_ESP].rrx + 3 * 4, 4, &tag)) {
            if (len <= kPageAllocBoundary) {
              taint::mark_allocated(
                  region, len, tag, globals::config.taint_pools ? MEM_UNINIT_HEAP : MEM_INIT);
              write_lin_mem(pcpu, region, len, (void *)globals::pool_taint_alloc);
            } else {
              taint::mark_allocated(region, len, tag, MEM_INIT);
            }

            uint32_t origin;
            if (globals::config.track_origins &&
                read_lin_mem(pcpu, pcpu->gen_reg[BX_32BIT_REG_ESP].rrx, 4, &origin)) {
              taint::set_origin(region, len, origin);
            }
          }
        }
        break;
      }

      case BP_POOL_FREE: {
        bx_address region = 0;
        if (read_lin_mem(pcpu, pcpu->gen_reg[BX_32BIT_REG_ESP].rrx + 1 * 4, 4, &region)) {
          taint::mark_free(region);
        }
        break;
      }
    }
  } else if (opcode == BX_IA_REP_MOVSB_YbXb || opcode == BX_IA_REP_MOVSD_YdXd) {
    globals::rep_movs = true;
  } else if (globals::config.taint_stack &&
             (opcode == BX_IA_SUB_GdEd || opcode == BX_IA_SUB_EdGd || opcode == BX_IA_SUB_EdId ||
              opcode == BX_IA_ADD_GdEd || opcode == BX_IA_ADD_EdGd || opcode == BX_IA_ADD_EdId ||
              opcode == BX_IA_AND_GdEd || opcode == BX_IA_ADD_EdGd || opcode == BX_IA_AND_EdId ||
              opcode == BX_IA_XCHG_ERXEAX) &&
             (i->dst() == BX_32BIT_REG_ESP)) {
    if (windows::check_kernel_addr(pcpu->gen_reg[BX_32BIT_REG_ESP].rrx)) {
      globals::esp_change = true;
      globals::esp_value = pcpu->gen_reg[BX_32BIT_REG_ESP].rrx;
    }
  }
}

// Callback invoked after execution of each instruction takes place.
void bx_instr_after_execution(unsigned cpu, bxInstruction_c *i) {
  globals::rep_movs = false;

  if (globals::esp_change) {
    BX_CPU_C *pcpu = BX_CPU(cpu);
    uint32_t new_esp = pcpu->gen_reg[BX_32BIT_REG_ESP].rrx;

    if (new_esp < globals::esp_value) {
      uint32_t length = globals::esp_value - new_esp;

      if (length <= kTaintHelperAllocSize) {
        taint::mark_allocated(new_esp, length, 0xaabbccdd, MEM_UNINIT_STACK);
        write_lin_mem(pcpu, new_esp, length, (void *)globals::stack_taint_alloc);

        if (globals::config.track_origins) {
          uint32_t origin = pcpu->prev_rip;

          if (i->getIaOpcode() == BX_IA_SUB_GdEd &&
              i->dst() == BX_32BIT_REG_ESP &&
              i->src() == BX_32BIT_REG_EAX) {
            // SUB ESP, EAX is a special construct used in generic function prologue
            // functions such as __SEH_prolog4. In order to obtain a real unique
            // origin of the allocation, we must read it from stack.
            uint32_t real_origin = 0; 
            read_lin_mem(pcpu, pcpu->gen_reg[BX_32BIT_REG_EBP].rrx - 2 * 4, 4, &real_origin);
            
            if (windows::check_kernel_addr(real_origin)) {
              origin = real_origin;
            }
          } else if (i->getIaOpcode() == BX_IA_XCHG_ERXEAX && i->dst() == BX_32BIT_REG_ESP) {
            // XCHG ESP, EAX is a special construct used in nt!_alloca_probe. In
            // order to obtain the real unique origin of the allocation, we must
            // read it from [EAX].
            uint32_t real_origin = 0; 
            read_lin_mem(pcpu, pcpu->gen_reg[BX_32BIT_REG_EAX].rrx, 4, &real_origin);
            
            if (windows::check_kernel_addr(real_origin)) {
              origin = real_origin;
            }
          }

          taint::set_origin(new_esp, length, origin);
        }
      }
    }

    globals::esp_change = false;
    globals::esp_value = 0;
  }
}

