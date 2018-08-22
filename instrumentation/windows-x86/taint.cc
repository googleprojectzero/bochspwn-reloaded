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

#include <algorithm>

#include "common.h"
#include "mem_interface.h"

namespace taint {

// Indicates if a pool byte has been written to.
uint8_t *written;
// Stores information about allocation sizes.
uint32_t *alloc_size;
// Stores information about the beginning of an allocation.
uint32_t *alloc_addr;
// Stores information about allocation tags.
uint32_t *alloc_tags;
// Stores information about allocation origins.
uint32_t *alloc_origins;

// Helper allocations for shadow memory dumps.
uint8_t *init_page;
uint8_t *shadow_mem_dump_buf;

void initialize(bool track_origins, bool shadow_mem_dump) {
  const size_t _2G = 2 * 1024 * 1024 * 1024LL;

  written = (uint8_t *)malloc(_2G);
  alloc_size = (uint32_t *)malloc(_2G * sizeof(uint32_t) >> 3);
  alloc_addr = (uint32_t *)malloc(_2G * sizeof(uint32_t) >> 3);
  alloc_tags = (uint32_t *)malloc(_2G * sizeof(uint32_t) >> 3);
  if (track_origins) {
    alloc_origins = (uint32_t *)malloc(_2G * sizeof(uint32_t) >> 3);
  }

  if (shadow_mem_dump) {
    init_page = (uint8_t *)malloc(4096);
    memset(init_page, MEM_INIT, 4096);

    shadow_mem_dump_buf = (uint8_t *)malloc(_2G / 4096);
  }

  assert(written != NULL);
  assert(alloc_size != NULL);
  assert(alloc_addr != NULL);
  assert(alloc_tags != NULL);
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
  free(alloc_tags);
  free(alloc_origins);

  written = NULL;
  alloc_size = NULL;
  alloc_addr = NULL;
  alloc_tags = NULL;
  alloc_origins = NULL;
}

void set_init_type(bx_address lin, unsigned int len, uint8_t init_type) {
  memset(&written[LIN_TO_IDX(lin)], init_type, len);
}

void mark_allocated(bx_address lin, unsigned int len, uint32_t tag, uint8_t init_type) {
  // Skip 0-sized allocations entirely. Nothing to do.
  if (len == 0) {
    return;
  }

  // Set the init meta.
  set_init_type(lin, len, init_type);

  // Set the allocation size and tag for the starting address of the
  // allocation.
  alloc_size[LIN_TO_IDX_ALIGNED(lin)] = len;
  alloc_tags[LIN_TO_IDX_ALIGNED(lin)] = tag;

  // Set information about the start of allocation.
  unsigned int start_idx = LIN_TO_IDX_ALIGNED(lin);
  unsigned int end_idx = LIN_TO_IDX_ALIGNED(lin + len - 1);
  for (unsigned int i = start_idx; i <= end_idx; i++) {
    alloc_addr[i] = lin;
  }
}

void mark_free(bx_address lin) {
  unsigned int len = alloc_size[LIN_TO_IDX_ALIGNED(lin)];

  // If the length of the allocation is not recognized, do nothing.
  if (len == 0) {
    return;
  }

  // Mark all bytes in range as free.
  set_init_type(lin, len, MEM_INIT);

  // Remove size and tag information.
  alloc_size[LIN_TO_IDX_ALIGNED(lin)] = 0;
  alloc_tags[LIN_TO_IDX_ALIGNED(lin)] = 0;

  // Clear out allocation address information.
  unsigned int start_idx = LIN_TO_IDX_ALIGNED(lin);
  unsigned int end_idx = LIN_TO_IDX_ALIGNED(lin + len - 1);
  memset(&alloc_addr[start_idx], 0, (end_idx - start_idx + 1) * sizeof(uint32_t));
}

access_type check_access(BX_CPU_C *pcpu, bx_address lin, unsigned int len) {
  access_type ret = ACCESS_VALID;

  for (unsigned int i = 0; i < len; i++) {
    if (written[LIN_TO_IDX(lin + i)] != MEM_INIT) {
      uint8_t byte = 0;
      read_lin_mem(pcpu, lin + i, 1, &byte);

      if (byte != kPoolTaintByte && byte != kStackTaintByte) {
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

bool get_alloc_info(bx_address lin, bx_address *base, unsigned int *size, uint32_t *tag) {
  bx_address alloc_base = alloc_addr[LIN_TO_IDX_ALIGNED(lin)];

  if (alloc_base == 0) {
    return false;
  }

  *size = alloc_size[LIN_TO_IDX_ALIGNED(alloc_base)];
  *tag = alloc_tags[LIN_TO_IDX_ALIGNED(alloc_base)];
  *base = alloc_base;
  return true;
}

void get_metadata(bx_address lin, unsigned int len, uint8_t *meta_init) {
  memcpy(meta_init, &written[LIN_TO_IDX(lin)], len);
}

void set_origin(bx_address lin, unsigned int len, uint32_t origin) {
  if (alloc_origins == NULL || len == 0) {
    return;
  }

  // Set information about the allocation origin.
  unsigned int start_idx = LIN_TO_IDX_ALIGNED(lin);
  unsigned int end_idx = LIN_TO_IDX_ALIGNED(lin + len - 1);
  for (unsigned int i = start_idx; i <= end_idx; i++) {
    alloc_origins[i] = origin;
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
  for (unsigned int offset = 0; offset < 0x80000000; offset += 0x1000) {
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

  size_t write_count = 512 * 1024;
  if (fwrite(shadow_mem_dump_buf, 1, write_count, f) != write_count) {
    fclose(f);
    return false;
  }

  fclose(f);
  return true;
}

}  // namespace taint

