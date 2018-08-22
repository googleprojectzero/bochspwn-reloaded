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

#ifndef BOCHSPWN_TAINT_H_
#define BOCHSPWN_TAINT_H_

#include "bochs.h"

#include <stdint.h>
#include <unordered_map>

namespace taint {

#define LIN_TO_IDX(lin) ((lin) >> 3)

// ------------------------------------------------------------------
// Global variables.
// ------------------------------------------------------------------
extern uint8_t *taint_area;
extern std::unordered_map<uint64_t, uint64_t> origins;

// ------------------------------------------------------------------
// Constants.
// ------------------------------------------------------------------
const uint64_t kTaintAreaBase = 0xffff800000000000;
const uint64_t kTaintAreaSize = 0x0000800000000000 / 8;

enum access_type {
  // All bytes in verified memory range are known to be initialized.
  ACCESS_VALID,
  // Some bytes in verified memory range are known to be uninitialized
  // (filled with a marker byte).
  ACCESS_INVALID,
  // There is a mismatch between the memory metadata and actual contents.
  METADATA_MARKER_MISMATCH
};

// ------------------------------------------------------------------
// Public interface.
// ------------------------------------------------------------------

// Initialize internal structures.
void initialize();

// Destroy internal structures.
void destroy();

// Copy taint between two memory locations.
void copy_taint(uint64_t dst, uint64_t src, uint64_t size);

// Set the taint bit for a memory area to a specific state.
void set_taint(uint64_t base, uint64_t size, bool tainted);

// Check if any byte within the specified range is currently tainted.
access_type check_taint(BX_CPU_C *pcpu, uint64_t base, uint64_t size, uint64_t *tainted_offset);

// Obtain a shadow memory representation of the specific region.
void get_shadow_memory(uint64_t address, uint64_t size, uint8_t *shadow_memory);

// Origin handling functions.
void set_origin(bx_address lin, uint64_t len, uint64_t origin);
uint64_t get_origin(bx_address lin);
void copy_origin(bx_address dst, bx_address src, uint64_t len);

}  // namespace taint

#endif  // BOCHSPWN_TAINT_H_
