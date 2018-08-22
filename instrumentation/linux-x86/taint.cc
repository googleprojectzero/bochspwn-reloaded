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

#include "common.h"
#include "mem_interface.h"

namespace taint {

// Indicates if a byte in the guest memory is (un)initialized.
uint8_t *written;
// Stores information about allocation sizes.
uint32_t *alloc_size;
// Stores information about the beginning of an allocation.
uint32_t *alloc_addr;
// Stores information about allocation flags.
uint32_t *alloc_flags;
// Stores information about allocation origins.
uint32_t *alloc_origins;

// Helper allocations for shadow memory dumps.
uint8_t *init_page;
uint8_t *shadow_mem_dump_buf;

void initialize(bool track_origins, bool shadow_mem_dump) {
  const size_t _1G = 1024 * 1024 * 1024LL;

  written = (uint8_t *)malloc(_1G);
  alloc_size = (uint32_t *)malloc(_1G * sizeof(uint32_t) >> 3);
  alloc_addr = (uint32_t *)malloc(_1G * sizeof(uint32_t) >> 3);
  alloc_flags = (uint32_t *)malloc(_1G * sizeof(uint32_t) >> 3);
  if (track_origins) {
    alloc_origins = (uint32_t *)malloc(_1G * sizeof(uint32_t) >> 3);
  }

  if (shadow_mem_dump) {
    init_page = (uint8_t *)malloc(4096);
    memset(init_page, MEM_INIT, 4096);

    shadow_mem_dump_buf = (uint8_t *)malloc(_1G / 4096);
  }

  assert(written != NULL);
  assert(alloc_size != NULL);
  assert(alloc_addr != NULL);
  assert(alloc_flags != NULL);
  if (track_origins) {
    assert(alloc_origins != NULL);
  }
  if (shadow_mem_dump) {
    assert(init_page != NULL);
    assert(shadow_mem_dump_buf != NULL);
  }
}

void destroy() {
  free(written);
  free(alloc_size);
  free(alloc_addr);
  free(alloc_flags);
  free(alloc_origins);

  written = NULL;
  alloc_size = NULL;
  alloc_addr = NULL;
  alloc_flags = NULL;
  alloc_origins = NULL;
}

void mark_init(bx_address lin, unsigned int len) {
  memset(&written[LIN_TO_IDX(lin)], MEM_INIT, len);
}

void mark_uninit(bx_address lin, unsigned int len, uint8_t type) {
  memset(&written[LIN_TO_IDX(lin)], type, len);
}

void mark_allocated(bx_address lin, unsigned int len, uint32_t flags, const bool *inited) {
  // Set the initialization bits for all bytes, if the information is available.
  if (inited != NULL) {
    if (*inited) {
      mark_init(lin, len);
    } else {
      mark_uninit(lin, len, MEM_UNINIT_HEAP);
    }
  }

  // Set the allocation size and flags for the starting address of the
  // allocation.
  alloc_size[LIN_TO_IDX_ALIGNED(lin)] = len;
  alloc_flags[LIN_TO_IDX_ALIGNED(lin)] = flags;

  // Set information about the start of allocation.
  for (unsigned int i = 0; i < len; i++) {
    alloc_addr[LIN_TO_IDX_ALIGNED(lin + i)] = lin;
  }
}

void mark_free(bx_address lin) {
  unsigned int len = alloc_size[LIN_TO_IDX_ALIGNED(lin)];

  // Mark all bytes in range as free.
  mark_init(lin, len);

  // Remove size and flags information.
  alloc_size[LIN_TO_IDX_ALIGNED(lin)] = 0;
  alloc_flags[LIN_TO_IDX_ALIGNED(lin)] = 0;

  // Clear out allocation address information.
  memset(&alloc_addr[LIN_TO_IDX_ALIGNED(lin)], 0, (len >> 3) * sizeof(uint32_t));
}

access_type check_access(BX_CPU_C *pcpu, bx_address lin, unsigned int len) {
  access_type ret = ACCESS_VALID;

  for (unsigned int i = 0; i < len; i++) {
    if (written[LIN_TO_IDX(lin + i)] != MEM_INIT) {
      uint8_t byte = 0;
      read_lin_mem(pcpu, lin + i, 1, &byte);

      if (byte != kHeapTaintByte && byte != kStackTaintByte) {
        return METADATA_PADDING_MISMATCH;
      } else {
        ret = ACCESS_INVALID;
      }
    }
  }

  return ret;
}

void copy_taint(bx_address dst, bx_address src, unsigned int len) {
  src = LIN_TO_IDX(src);
  dst = LIN_TO_IDX(dst);
  memcpy(&written[dst], &written[src], len);
}

bool get_alloc_info(bx_address lin, bx_address *base, unsigned int *size, uint32_t *flags) {
  bx_address alloc_base = alloc_addr[LIN_TO_IDX_ALIGNED(lin)];

  if (alloc_base == 0) {
    return false;
  }

  *size = alloc_size[LIN_TO_IDX_ALIGNED(alloc_base)];
  *flags = alloc_flags[LIN_TO_IDX_ALIGNED(alloc_base)];
  *base = alloc_base;
  return true;
}

void get_metadata(bx_address lin, unsigned int len, uint8_t *meta_init) {
  memcpy(meta_init, &written[LIN_TO_IDX(lin)], len);
}

void set_origin(bx_address lin, unsigned int len, uint32_t origin) {
  if (alloc_origins == NULL) {
    return;
  }

  // Set information about the allocation origin.
  for (unsigned int i = 0; i < len; i++) {
    alloc_origins[LIN_TO_IDX_ALIGNED(lin + i)] = origin;
  }
}

uint32_t get_origin(bx_address lin) {
  if (alloc_origins == NULL) {
    return 0xbaadbaad;
  }

  return alloc_origins[LIN_TO_IDX_ALIGNED(lin)];
}

void copy_origin(bx_address dst, bx_address src, unsigned int len) {
  if (alloc_origins == NULL) {
    return;
  }

  for (unsigned int i = 0; i < len; i++) {
    alloc_origins[LIN_TO_IDX_ALIGNED(dst + i)] = alloc_origins[LIN_TO_IDX_ALIGNED(src + i)];
  }
}

bool dump_state(const char *filename) {
  for (unsigned int offset = 0; offset < 0x40000000; offset += 0x1000) {
    uint8_t page_byte = MEM_INIT;
    if (memcmp(&written[offset], init_page, 0x1000) != 0) {
      for (unsigned int page_offset = 0; page_offset < 0x1000; page_offset++) {
        if (written[offset + page_offset] != MEM_INIT) {
          page_byte = written[offset + page_offset];
          break;
        }
      }
    }

    shadow_mem_dump_buf[offset / 0x1000] = page_byte;
  }

  FILE *f = fopen(filename, "w+b");
  if (f == NULL) {
    return false;
  }

  size_t write_count = 256 * 1024;
  if (fwrite(shadow_mem_dump_buf, 1, write_count, f) != write_count) {
    fclose(f);
    return false;
  }

  fclose(f);
  return true;
}

}  // namespace taint

