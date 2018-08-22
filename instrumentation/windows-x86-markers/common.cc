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

#include <unordered_set>

#include "cpu/cpu.h"

#include "os_windows.h"

// See instrumentation.h for globals' documentation.
namespace globals {
  bochspwn_config config;
  std::unordered_set<uint32_t> origins;
  bx_address nt_base;
  uint32_t *taint_alloc;
  bool esp_change;
  uint32_t esp_value;
}  // namespace globals

void fill_pattern(uint32_t *array, uint32_t bytes) {
  for (uint32_t i = 0; i < bytes; i += sizeof(uint32_t)) {
    array[i / sizeof(uint32_t)] = 0xCAFE0000 + (i / sizeof(uint32_t));
  }
}

void fill_uint32(uint32_t *array, uint32_t value, uint32_t bytes) {
  for (uint32_t i = 0; i < bytes; i += sizeof(uint32_t)) {
    array[i / sizeof(uint32_t)] = value;
  }
}

bool get_nth_caller(BX_CPU_C *pcpu, unsigned int idx, uint32_t *caller_address) {
  if (idx == 0) {
    *caller_address = pcpu->prev_rip;
    return true;
  }

  uint32_t ip = pcpu->prev_rip;
  uint32_t bp = pcpu->gen_reg[BX_32BIT_REG_EBP].rrx;

  unsigned int i;
  for (i = 0;
       i < idx && windows::check_kernel_addr(ip) && windows::check_kernel_addr(bp);
       i++) {
    if (!bp ||
        !read_lin_mem(pcpu, bp + sizeof(uint32_t), sizeof(uint32_t), &ip) ||
        !read_lin_mem(pcpu, bp, sizeof(uint32_t), &bp)) {
      return false;
    }
  }

  if (i == idx) {
    *caller_address = ip;
    return true;
  }

  return false;
}

