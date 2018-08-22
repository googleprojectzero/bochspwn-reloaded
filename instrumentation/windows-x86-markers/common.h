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

#ifndef BOCHSPWN_COMMON_H_
#define BOCHSPWN_COMMON_H_

#include <stdint.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unordered_set>
#include <vector>

// ------------------------------------------------------------------
// Constants.
// ------------------------------------------------------------------
const char kConfFileEnvVariable[] = "BOCHSPWN_CONF";
const uint32_t kPoolTaintDword = 0x3bdd78ec;
const uint32_t kStackTaintDword = 0x7345c6f1;
const unsigned int kTaintHelperAllocSize = 16 * 4096;

// Types of breakpoints set in the Windows kernel.
#define BP_POOL_ALLOC        0

// ------------------------------------------------------------------
// Internal enumerations and structures.
// ------------------------------------------------------------------

// Generic settings read from .ini configuration file.
struct bochspwn_config {
  // Path to output log files containing a list of allocation origins.
  char *origin_log_path;

  // Handle to origin log file.
  FILE *origin_log_handle;

  // Guest operating system version, used as the name for system-specific
  // .ini configuration section.
  char *os_version;

  // Indicates which Nth code origin address in the call stack is used as
  // allocation padding, 0 = direct allocator.
  uint32_t callstack_origin_index;

  // Initialize fields with typical values for safety.
  bochspwn_config() : origin_log_path(strdup("origins.txt")), origin_log_handle(NULL),
                      os_version(strdup("win7_32")), callstack_origin_index(0) { }

  ~bochspwn_config() {
    if (origin_log_path != NULL) {
      free(origin_log_path);
    }

    if (origin_log_handle != NULL) {
      fclose(origin_log_handle);
    }

    if (os_version != NULL) {
      free(os_version);
    }
  }
};

// Included here to mitigate the header hell.
#include "bochs.h"
#include "cpu/cpu.h"
#include "mem_interface.h"

// ------------------------------------------------------------------
// Global helper functions.
// ------------------------------------------------------------------

// Fills an array of uint32_t items with a recognizable pattern.
void fill_pattern(uint32_t *array, uint32_t bytes);

// Fills an array of uint32_t items with a specific value.
void fill_uint32(uint32_t *array, uint32_t value, uint32_t bytes);

// Obtains the N-th indirect caller of the currently executed function. The
// value of 0 returns current EIP, and the value fo 1 returns the function's
// direct caller.
bool get_nth_caller(BX_CPU_C *pcpu, unsigned int idx, uint32_t *caller_address);

// ------------------------------------------------------------------
// Global helper macros.
// ------------------------------------------------------------------
#define READ_INI_STRING(file, section, name, buf, size) \
  if (!GetPrivateProfileStringA((section), (name), NULL, (buf), (size), (file))) {\
    fprintf(stderr, "Unable to read the %s/%s string from configuration file.\n", \
            (section), (name));\
    return false;\
  }

#define READ_INI_INT(file, section, name, buf, size, dest) \
  READ_INI_STRING((file), (section), (name), (buf), (size))\
  if (!sscanf(buf, "%i", (dest))) {\
    fprintf(stderr, "Unable to parse the %s/%s value as integer.\n", \
            (section), (name));\
    return false;\
  }

#define READ_INI_ULL(file, section, name, buf, size, dest) \
  READ_INI_STRING((file), (section), (name), (buf), (size))\
  if (!sscanf(buf, "%llx", (dest))) {\
    fprintf(stderr, "Unable to parse the %s/%s value as integer.\n", \
            (section), (name));\
    return false;\
  }

// ------------------------------------------------------------------
// Global objects.
// ------------------------------------------------------------------
namespace globals {

// Generic configuration.
extern bochspwn_config config;

// List of unique pool/stack allocation origins.
extern std::unordered_set<uint32_t> origins;

// Base address of ntoskrnl.exe optimized for quick access.
extern bx_address nt_base;

// A large helper allocation filled with taint data.
extern uint32_t *taint_alloc;

// An instruction-scope marker indicating if the current instruction
// is one of the esp-modifying ones.
extern bool esp_change;

// If Esp is being modified by the current instruction, this variable
// stores its original value from before its execution.
extern uint32_t esp_value;

}  // namespace globals

#endif  // BOCHSPWN_COMMON_H_

