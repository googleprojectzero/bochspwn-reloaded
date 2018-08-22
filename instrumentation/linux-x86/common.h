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
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "logging.pb.h"

// ------------------------------------------------------------------
// Constants.
// ------------------------------------------------------------------
const char kConfFileEnvVariable[] = "BOCHSPWN_CONF";
const uint8_t kHeapTaintByte = 0xaa;
const uint8_t kStackTaintByte = 0xbb;
const unsigned int kTaintHelperAllocSize = 16 * 4096;

#define __GFP_ZERO 0x8000

// Types of breakpoints set in the Linux kernel.
#define BP_KMALLOC_PROLOGUE      0
#define BP_VMALLOC_PROLOGUE      1
#define BP_ALLOC_EPILOGUE        2
#define BP_ALLOC_FREE            3
#define BP_CACHE_CREATE_PROLOGUE 4
#define BP_CACHE_CREATE_EPILOGUE 5
#define BP_CACHE_DESTROY         6
#define BP_CACHE_ALLOC_PROLOGUE  7
#define BP_CACHE_FREE            8
#define BP_CACHE_CONSTRUCTOR     9
#define BP_BLACKLISTED           10

// ------------------------------------------------------------------
// Internal enumerations and structures.
// ------------------------------------------------------------------

// Generic settings read from .ini configuration file.
struct bochspwn_config {
  // Path to output log file.
  char *log_path;

  // Handle to output file.
  FILE *file_handle;

  // Guest operating system version, used as the name for system-specific
  // .ini configuration section.
  char *os_version;

  // Maximum number of stack frames stored in a single memory access
  // descriptor.
  uint32_t callstack_length;

  // Indicates if heap allocations should be tainted.
  uint32_t taint_heap;

  // Indicates if stack "allocations" made by executing SUB ESP, imm32 and
  // similar instructions should be tainted.
  uint32_t taint_stack;

  // Indicates if the stack/heap allocation origins should be saved (which
  // takes additional 8GB of memory and some CPU overhead).
  uint32_t track_origins;

  // Indicates if callstack-based uniquization should take place.
  uint32_t uniquize;

  // Indicates if an interrupt should be generated within the guest OS if
  // an error is encountered.
  uint32_t break_on_bug;

  // Indicates if only kernel--->user memory disclosures should be reported in
  // the log files, or all accesses to uninitialized memory.
  uint32_t only_kernel_to_user;

  // Indicates if dumping shadow memory state to files is enabled.
  uint32_t dump_shadow_to_files;

  // Indicates the interval between subsequent shadow memory dumps, in seconds.
  uint32_t dump_shadow_interval;

  // Path of the directory where shadow memory dumps are saved.
  char *dump_shadow_path;

  // Initialize fields with typical values for safety.
  bochspwn_config() : log_path(strdup("memlog.txt")), file_handle(NULL),
                      os_version(strdup("ubuntu_16.10_x86")), taint_heap(1),
                      taint_stack(0), track_origins(0), uniquize(0),
                      break_on_bug(0), only_kernel_to_user(0),
                      dump_shadow_to_files(0), dump_shadow_path(NULL)  { }

  ~bochspwn_config() {
    if (log_path != NULL) {
      free(log_path);
    }

    if (os_version != NULL) {
      free(os_version);
    }

    if (file_handle != NULL) {
      fclose(file_handle);
    }
  }
};

// Included here to mitigate the header hell.
#include "bochs.h"
#include "cpu/cpu.h"
#include "mem_interface.h"

// Stack-trace descriptor, contains a full list of absolute virtual
// function call addresses.
struct stack_trace {
  std::vector<uint64_t> trace;

  bool operator< (const stack_trace& a) const {
    return (trace < a.trace);
  }
  bool operator != (const stack_trace& a) const {
    return (trace != a.trace);
  }
};

// Information about a known kernel module currently loaded in the
// operating system.
struct module_info {
  uint64_t module_base;
  uint64_t module_size;
  char *module_name;

  module_info() : module_base(0), module_size(0), module_name(NULL) {}
  module_info(bx_address b, bx_address s, const char *n) :
    module_base(b), module_size(s), module_name(strdup(n)) {}
  ~module_info() { if (module_name) free(module_name); }
};

// ------------------------------------------------------------------
// Global helper functions.
// ------------------------------------------------------------------

// Identifies loaded module based on a virtual address.
module_info* find_module(bx_address item);

// Formats string as a hex binary blob.
std::string format_hex(const std::string& data);

// Translates memory access type enum into textual representation.
const char *translate_mem_access(bug_report_t::mem_access_type type);

// Generates an interrupt exception in the guest operating system.
void invoke_guest_int3(BX_CPU_C *pcpu);

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
  READ_INI_STRING((file), (section), (name), (buf), (size));\
  dest = strtoul(buf, NULL, 0);

// ------------------------------------------------------------------
// Global objects.
// ------------------------------------------------------------------
namespace globals {

// Generic configuration.
extern bochspwn_config config;

// Global information about all currently known kernel modules. Updated
// lazily, only when an unknown driver is encountered.
extern std::vector<module_info *> modules;

// If known_callstack_item.find(address) != .end(), it means that the address
// has been already encountered as a part of a stack trace.
extern std::unordered_set<bx_address> known_callstack_item;

// Large helper allocations filled with the heap/stack taint bytes (both of size
// kTaintHelperAllocSize).
extern uint8_t *heap_taint_alloc;
extern uint8_t *stack_taint_alloc;

// An instruction-scope marker (set by before_execution, unset by
// after_execution) indicating if the current instruction (handled by
// lin_access) is a member of the REP MOVSx family, in which case it is
// handled in a special way.
extern bool rep_movs;

// An instruction-scope marker similar to rep_movs indicating if the
// current instruction is one of the esp-modifying ones.
extern bool esp_change;

// If Esp is being modified by the current instruction, this variable
// stores its original value from before its execution.
extern uint32_t esp_value;

// Indicates if the strict-checking mode is enabled for a given stack pointer
// value, meaning that all memory references at that ESP are checked for
// uninitialized memory, not just copying to user-mode. This is triggered by the
// LFENCE instruction and disabled by SFENCE, which surround the operand-reading
// part of the put_user() macro.
extern std::unordered_set<uint32_t> strict_checking;

// Saved information about currently active kmem caches.
struct kmem_cache {
  uint32_t size;
  uint32_t constructor;
};
extern std::unordered_map<uint32_t, kmem_cache> kmem_caches;
extern std::unordered_map<uint32_t, uint32_t> kmem_cache_constructor_to_size;

// The specifics of requested cache creations per stack pointer, as captured by
// the cache creator prologue hook.
extern std::unordered_map<uint32_t, kmem_cache> per_site_cache_reqs;

// The specifics (length, flags, cache) of requested heap allocations per stack
// pointer, as captured by the allocator prologue hook.
struct alloc_request {
  uint32_t cache;
  uint32_t length;
  uint32_t flags;
};
extern std::unordered_map<uint32_t, alloc_request> per_site_alloc_reqs;

// Stores information on whether a custom breakpoint was installed by the
// instrumentation (in order to break into kernel debugger), and the location
// that was modified in order to insert it.
extern bool bp_active;
extern uint32_t bp_address;
extern uint8_t bp_orig_byte;

}  // namespace globals

#endif  // BOCHSPWN_COMMON_H_

