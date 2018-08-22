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

#define LIN_TO_IDX(lin) ((lin) - 0x80000000)
#define LIN_TO_IDX_ALIGNED(lin) (((lin) - 0x80000000) >> 3)

// Tainted memory types.
#define MEM_INIT         0x00
#define MEM_UNINIT_HEAP  0xfe
#define MEM_UNINIT_STACK 0xff

namespace taint {

enum access_type {
  // All bytes in verified memory range are known to be initialized.
  ACCESS_VALID,
  // Some bytes in verified memory range are known to be uninitialized
  // (filled with a padding byte).
  ACCESS_INVALID,
  // There is a mismatch between the memory metadata and actual contents.
  METADATA_PADDING_MISMATCH
};

// Initialize internal structures.
void initialize(bool track_origins, bool shadow_mem_dump);

// Destroy internal structures.
void destroy();

// Mark the specific memory region as (un)initialized.
void set_init_type(bx_address lin, unsigned int len, uint8_t init_type);

// Mark a specific memory region as allocated. The additional information
// (eip) are used to ease the identification of a specific pool chunk.
void mark_allocated(bx_address lin, unsigned int len, uint32_t tag, uint8_t init_type);

// Mark the specific memory region as freed.
void mark_free(bx_address lin);

// Check if reading a specific memory range is valid, i.e. for all bytes in the
// range, check if they are known to be initialized.
access_type check_access(BX_CPU_C *pcpu, bx_address lin, unsigned int len);

// Copy taint (initialization) information for all bytes within two memory
// ranges.
void copy_taint(bx_address dst, bx_address src, unsigned int len);

// Returns allocation base, size and tag.
bool get_alloc_info(bx_address lin, bx_address *base, unsigned int *size, uint32_t *tag);

// Copy metadata bytes into external buffers.
void get_metadata(bx_address lin, unsigned int len, uint8_t *meta_init);

// Sets the origin of a specific allocation.
void set_origin(bx_address lin, unsigned int len, uint32_t origin);
uint32_t get_origin(bx_address lin);
void copy_origin(bx_address dst, bx_address src, unsigned int len);

// Dumps the current shadow memory state into a file.
bool dump_state(const char *filename);

}  // namespace taint

#endif  // BOCHSPWN_TAINT_H_

