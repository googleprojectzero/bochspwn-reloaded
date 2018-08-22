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

#include "taint.h"

#include <windows.h>

#include <time.h>

#include "bochs.h"

#include "common.h"
#include "mem_interface.h"

namespace taint {

// ------------------------------------------------------------------
// Global variables.
// ------------------------------------------------------------------
uint8_t *taint_area;
std::unordered_map<uint64_t, uint64_t> origins;

// ------------------------------------------------------------------
// Helper functions.
// ------------------------------------------------------------------
static LONG CALLBACK OvercommitHandler(
  _In_ PEXCEPTION_POINTERS ExceptionInfo
) {
  if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
    const uint8_t *excp_address = (uint8_t *)ExceptionInfo->ExceptionRecord->ExceptionInformation[1];
    if (excp_address >= taint_area && excp_address < &taint_area[kTaintAreaSize]) {
      if (VirtualAlloc((void *)((uint64_t)excp_address & (~0xffff)), 0x10000, MEM_COMMIT, PAGE_READWRITE)) {
        return EXCEPTION_CONTINUE_EXECUTION;
      }
    }
  }

  return EXCEPTION_CONTINUE_SEARCH;
}

void set_bit(uint64_t offset) {
  taint_area[offset / 8] |= (1 << (offset & 7));
}

void clear_bit(uint64_t offset) {
  taint_area[offset / 8] &= ~(1 << (offset & 7));
}

bool check_bit(uint64_t offset) {
  return ((taint_area[offset / 8] & (1 << (offset & 7))) != 0);
}

// ------------------------------------------------------------------
// Public interface.
// ------------------------------------------------------------------
void initialize() {
  // Reserve a memory region for the taint data.
  taint_area = (uint8_t *)VirtualAlloc(NULL, kTaintAreaSize, MEM_RESERVE, PAGE_READWRITE);

  // Register a VEH handler to commit taint memory touched in other taint
  // functions.
  AddVectoredExceptionHandler(/*FirstHandler=*/1, OvercommitHandler);
}

void destroy() {
  // Unregister the overcommit exception handler.
  RemoveVectoredExceptionHandler((void *)OvercommitHandler);
}

void copy_taint(uint64_t dst, uint64_t src, uint64_t size) {
  dst -= kTaintAreaBase;
  src -= kTaintAreaBase;

  for (uint64_t i = 0; i < size; i++) {
    if (check_bit(src + i)) {
      set_bit(dst + i);
    } else {
      clear_bit(dst + i);
    }
  }
}

void set_taint(uint64_t base, uint64_t size, bool tainted) {
  base -= kTaintAreaBase;

  if (tainted) {
    for (uint64_t i = 0; i < size; i++) {
      set_bit(base + i);
    }
  } else {
    for (uint64_t i = 0; i < size; i++) {
      clear_bit(base + i);
    }
  }
}

access_type check_taint(BX_CPU_C *pcpu, uint64_t base, uint64_t size, uint64_t *tainted_offset) {
  const uint64_t shifted_base = base - kTaintAreaBase;

  for (uint64_t i = 0; i < size; i++) {
    if (check_bit(shifted_base + i)) {
      uint8_t byte = 0;
      read_lin_mem(pcpu, base + i, 1, &byte);

      if (byte == kPoolTaintByte || byte == kStackTaintByte) {
        *tainted_offset = i;
        return ACCESS_INVALID;
      } else {
        return METADATA_MARKER_MISMATCH;
      }
    }
  }

  return ACCESS_VALID;
}

void get_shadow_memory(uint64_t address, uint64_t size, uint8_t *shadow_memory) {
  address -= kTaintAreaBase;

  for (uint64_t i = 0; i < size; i++) {
    if (check_bit(address + i)) {
      shadow_memory[i] = 0xff;
    } else {
      shadow_memory[i] = 0x00;
    }
  }
}

void set_origin(bx_address lin, uint64_t len, uint64_t origin) {
  if (len == 0) {
    return;
  }

  uint64_t start_idx = LIN_TO_IDX(lin);
  uint64_t end_idx = LIN_TO_IDX(lin + len - 1);
  for (uint64_t i = start_idx; i <= end_idx; i++) {
    origins[i] = origin;
  }
}

uint64_t get_origin(bx_address lin) {
  auto it = origins.find(LIN_TO_IDX(lin));
  
  if (it == origins.end()) {
    return 0;
  }

  return it->second;
}

void copy_origin(bx_address dst, bx_address src, uint64_t len) {
  for (uint64_t i = 0; i < len; i++) {
    origins[LIN_TO_IDX(dst + i)] = origins[LIN_TO_IDX(src + i)];
  } 
}

}  // namespace taint

