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

#include "common.h"

#include "bochs.h"
#include "cpu/cpu.h"

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "mem_interface.h"

namespace globals {
  bochspwn_config config;
  std::vector<module_info *> modules;
  std::vector<module_info *> special_modules;
  std::unordered_set<bx_address> known_callstack_item;
  std::unordered_set<bx_address> known_origin;
  bx_address nt_base;
  std::unordered_map<bx_address, bool> is_address_memcpy;
  std::unordered_set<bx_address> rsp_locked;
  uint8_t *pool_taint_alloc;
  uint8_t *stack_taint_alloc;
  std::unordered_map<uint64_t, alloc_request> pending_allocs;
  bool rep_movs;
  bool rsp_change;
  uint64_t rsp_value;
  bool bp_active;
  uint64_t bp_address;
  uint8_t bp_orig_byte;
}  // namespace globals

// Given a kernel-mode virtual address, returns the image base of the
// corresponding module or NULL, if one is not found. Assuming that every
// executed address belongs to a valid PE address at any given time, not finding
// an address should be interpreted as a signal to update the current module
// database.
module_info *find_module(bx_address item) {
  size_t sz = globals::special_modules.size();

  // Prioritize the special_modules list, as it contains the most commonly
  // encountered images (e.g. ntoskrnl, win32k for Windows).
  for (size_t i = 0; i < sz; i++) {
    if (globals::special_modules[i]->module_base <= item &&
        globals::special_modules[i]->module_base + globals::special_modules[i]->module_size > item) {
      return globals::special_modules[i];
    }
  }

  // Search through the remaining known modules.
  sz = globals::modules.size();
  for (size_t i = 0; i < sz; i++) {
    if (globals::modules[i]->module_base <= item &&
        globals::modules[i]->module_base + globals::modules[i]->module_size > item) {
      return globals::modules[i];
    }
  }

  return NULL;
}

// Given a kernel driver name, returns an index of the corresponding module
// descriptor in globals::modules, or -1, if it's not found.
module_info *find_module_by_name(const std::string& module) {
  size_t sz = globals::special_modules.size();

  // Prioritize the special_modules list, as it contains the most commonly
  // encountered images (e.g. ntoskrnl, win32k for Windows).
  for (size_t i = 0; i < sz; i++) {
    if (globals::special_modules[i]->module_name == module) {
      return globals::special_modules[i];
    }
  }

  // Search through the remaining known modules.
  sz = globals::modules.size();
  for (size_t i = 0; i < sz; i++) {
    if (globals::modules[i]->module_name == module) {
      return globals::modules[i];
    }
  }

  return NULL;
}

std::string format_hex(const std::string& data) {
  std::string output;
  char buffer[256];

  for (size_t i = 0; i < data.size(); i += 16) {
    snprintf(buffer, sizeof(buffer), "%.8x: ", i);
    output += buffer;

    for (size_t j = 0; j < 16; j++) {
      if (i + j < data.size()) {
        snprintf(buffer, sizeof(buffer), "%.2x ", (unsigned char)data[i + j]);
      } else {
        strncpy(buffer, "?? ", sizeof(buffer));
      }
      output += buffer;
    }

    for (size_t j = 0; j < 16; j++) {
      if (i + j < data.size() && data[i + j] >= 0x20 && data[i + j] <= 0x7e) {
        snprintf(buffer, sizeof(buffer), "%c", data[i + j]);
      } else {
        strncpy(buffer, ".", sizeof(buffer));
      }
      output += buffer;
    }

    output += "\n";
  }

  return output;
}

std::string unhexlify(const std::string& data) {
  std::string decoded;

  for (size_t i = 0; i + 1 < data.size(); i += 2) {
    unsigned char nibbles[2];
    
    char c = tolower(data[i]);
    if (isdigit(c)) {
      nibbles[0] = c - '0';
    } else if (c >= 'a' && c <= 'f') {
      nibbles[0] = 10 + (c - 'a');
    } else {
      nibbles[0] = 0;
    }

    c = tolower(data[i + 1]);
    if (isdigit(c)) {
      nibbles[1] = c - '0';
    } else if (c >= 'a' && c <= 'f') {
      nibbles[1] = 10 + (c - 'a');
    } else {
      nibbles[1] = 0;
    }

    decoded += (nibbles[0] << 4) | nibbles[1];
  }

  return decoded;
}

void invoke_guest_int3(BX_CPU_C *pcpu, bool rip_is_cur_instr, bxInstruction_c *i) {
  bx_address rip = pcpu->gen_reg[BX_64BIT_REG_RIP].rrx;
  if (rip_is_cur_instr) {
    rip += i->ilen();
  }

  // Save information about the original code, so that it can be restored when
  // the breakpoint fires.
  globals::bp_active = true;
  globals::bp_address = rip;
  globals::bp_orig_byte = 0xcc;
  read_lin_mem(pcpu, rip, 1, &globals::bp_orig_byte);

  // Overwrite the next instruction with an INT3, which will trigger a
  // guest breakpoint.
  write_lin_mem(pcpu, rip, 1, (void *)"\xcc");
}

