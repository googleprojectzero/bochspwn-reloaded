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

#include <windows.h>

#include <stdint.h>
#include <stdarg.h>
#include <map>
#include <string>
#include <vector>

#include "bochs.h"
#include "cpu/cpu.h"
#include "disasm/disasm.h"

#include "breakpoints.h"
#include "common.h"
#include "instrument.h"
#include "os_windows.h"

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

  // Origin log path.
  READ_INI_STRING(config_path, "general", "origin_log_path", buffer, sizeof(buffer));
  config->origin_log_path = strdup(buffer);

  // System version.
  READ_INI_STRING(config_path, "general", "version", buffer, sizeof(buffer));
  config->os_version = strdup(buffer);

  // Read the callstack origin index setting.
  READ_INI_INT(config_path, "general", "callstack_origin_index", buffer, sizeof(buffer),
               &config->callstack_origin_index);

  // Comma-separated list of pool allocation routine offsets.
  std::vector<uint32_t> pool_allocs;
  READ_INI_STRING(config_path, "general", "pool_allocs", buffer, sizeof(buffer));
  parse_offset_list(buffer, &pool_allocs);
  set_breakpoints_bulk(pool_allocs, BP_POOL_ALLOC);

  return true;
}

static void save_origin(const uint32_t origin) {
  if (globals::config.origin_log_handle == NULL) {
    return;
  }

  if (globals::origins.find(origin) != globals::origins.end()) {
    return;
  }

  globals::origins.insert(origin);
  fprintf(globals::config.origin_log_handle, "%x\n", origin);
  fflush(globals::config.origin_log_handle);
}

static bool read_nth_origin(BX_CPU_C *pcpu, uint32_t index, uint32_t *origin) {
  if (index == 0) {
    *origin = pcpu->prev_rip;
    return true;
  }

  uint32_t bp = pcpu->gen_reg[BX_32BIT_REG_EBP].rrx;
  for (uint32_t i = 1; i < index; i++) {
    if (!windows::check_kernel_addr(bp) || !read_lin_mem(pcpu, bp, 4, &bp)) {
      return false;
    }
  }

  uint8_t test_byte;
  if (!read_lin_mem(pcpu, bp + 4, 4, origin) ||
      !windows::check_kernel_addr(*origin) ||
      !read_lin_mem(pcpu, *origin, 1, &test_byte)) {
    return false;
  }

  return true;
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
  globals::config.origin_log_handle = fopen(globals::config.origin_log_path, "wb");
  if (globals::config.origin_log_handle == NULL) {
    fprintf(stderr, "Unable to open the \"%s\" log file\n", globals::config.origin_log_path);
    abort();
  }
  setbuf(globals::config.origin_log_handle, NULL);

  // Allow the guest-specific part to initialize (read internal offsets etc).
  if (!windows::init(conf_path)) {
    fprintf(stderr, "Guest-specific initialization with file \"%s\" failed\n", conf_path);
    abort();
  }

  // Initialize the helper taint allocation.
  globals::taint_alloc = (uint32_t *)malloc(kTaintHelperAllocSize);
  //fill_pattern(globals::taint_alloc, kTaintHelperAllocSize);
}

// Callback invoked on destroying a Bochs CPU object.
void bx_instr_exit(unsigned cpu) {
  // Free helper allocations.
  free(globals::taint_alloc);
  globals::taint_alloc = NULL;
}

// Callback invoked before execution of each instruction takes place.
void bx_instr_before_execution(unsigned cpu, bxInstruction_c *i) {
  BX_CPU_C *pcpu = BX_CPU(cpu);
  bx_address pc = pcpu->prev_rip;

  // We're only really interested in protected mode, kernel-mode code.
  if (!pcpu->protected_mode() || !windows::check_kernel_addr(pc)) {
    return;
  }

  unsigned int opcode = i->getIaOpcode();
  if (opcode == BX_IA_RET_Op32_Iw) /* Handling of RETn opcode (allocators) */ {
    if (globals::nt_base == 0) {
      globals::nt_base = windows::get_nt_kernel_address(pcpu);
      if (globals::nt_base == 0) {
        return;
      }
    }

    // Check if it's one of the pool allocation routines.
    if (bp::check_breakpoint(pc - globals::nt_base) == BP_POOL_ALLOC) {
      bx_address region = pcpu->gen_reg[BX_32BIT_REG_EAX].rrx;
      if (region != 0) {
        unsigned int len;
        uint32_t tag, origin;

        if (read_lin_mem(pcpu, pcpu->gen_reg[BX_32BIT_REG_ESP].rrx + 2 * 4, 4, &len) &&
            read_lin_mem(pcpu, pcpu->gen_reg[BX_32BIT_REG_ESP].rrx + 3 * 4, 4, &tag)) {
          bool origin_found = false;
          if (globals::config.callstack_origin_index == 0) {
            origin_found = read_lin_mem(pcpu, pcpu->gen_reg[BX_32BIT_REG_ESP].rrx, 4, &origin);
          } else {
            origin_found = read_nth_origin(pcpu, globals::config.callstack_origin_index, &origin);
          }

          if (origin_found && len <= kTaintHelperAllocSize) {
            fill_uint32(globals::taint_alloc, origin ^ kPoolTaintDword, len);
            write_lin_mem(pcpu, region, len, (void *)globals::taint_alloc);
           
            save_origin(origin);
          }
        }
      }
    }
  } else if ((opcode == BX_IA_SUB_GdEd || opcode == BX_IA_SUB_EdGd || opcode == BX_IA_SUB_EdId ||
              opcode == BX_IA_ADD_GdEd || opcode == BX_IA_ADD_EdGd || opcode == BX_IA_ADD_EdId ||
              opcode == BX_IA_AND_GdEd || opcode == BX_IA_ADD_EdGd || opcode == BX_IA_AND_EdId) &&
             (i->dst() == BX_32BIT_REG_ESP)) {
    if (windows::check_kernel_addr(pcpu->gen_reg[BX_32BIT_REG_ESP].rrx)) {
      globals::esp_change = true;
      globals::esp_value = pcpu->gen_reg[BX_32BIT_REG_ESP].rrx;
    }
  }
}

// Callback invoked after execution of each instruction takes place.
void bx_instr_after_execution(unsigned cpu, bxInstruction_c *i) {
  if (globals::esp_change) {
    BX_CPU_C *pcpu = BX_CPU(cpu);
    const uint32_t new_esp = pcpu->gen_reg[BX_32BIT_REG_ESP].rrx;

    if (new_esp < globals::esp_value) {
      const uint32_t length = globals::esp_value - new_esp;

      if (length <= kTaintHelperAllocSize) {
        uint32_t origin = pcpu->prev_rip;
        bool origin_found = true;

        if (globals::config.callstack_origin_index == 0) {
          // SUB ESP, EAX is a special construct used in generic function prologue
          // functions such as __SEH_prolog4. In order to obtain a real unique
          // origin of the allocation, we must read it from stack.
          if (i->getIaOpcode() == BX_IA_SUB_GdEd &&
              i->dst() == BX_32BIT_REG_ESP &&
              i->src() == BX_32BIT_REG_EAX) {
            uint32_t real_origin = 0; 
            read_lin_mem(pcpu, pcpu->gen_reg[BX_32BIT_REG_EBP].rrx - 2 * 4, 4, &real_origin);
            
            if (windows::check_kernel_addr(real_origin)) {
              origin = real_origin;
            }
          }
        } else {
          origin_found = read_nth_origin(pcpu, globals::config.callstack_origin_index, &origin);
        }
        
        if (origin_found) {
          fill_uint32(globals::taint_alloc, origin ^ kStackTaintDword, length);
          write_lin_mem(pcpu, new_esp, length, (void *)globals::taint_alloc);

          save_origin(origin);
        }
      }
    }

    globals::esp_change = false;
    globals::esp_value = 0;
  }
}

