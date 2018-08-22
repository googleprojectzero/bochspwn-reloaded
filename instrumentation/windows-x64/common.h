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

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "bochs.h"
#include "cpu/cpu.h"

// ------------------------------------------------------------------
// Constants.
// ------------------------------------------------------------------
const char kConfFileEnvVariable[] = "BOCHSPWN_CONF";
const uint8_t kPoolTaintByte = 0xaa;
const uint8_t kStackTaintByte = 0xbb;
const unsigned int kTaintHelperAllocSize = 16 * 4096;

// The MSR used to store the kernel-mode SYSENTER entry point address.
#define MSR_LSTAR 0xc0000082

// Types of breakpoints set in the Windows kernel.
#define BP_POOL_ALLOC_PROLOGUE 0
#define BP_POOL_ALLOC_EPILOGUE 1

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

  // If non-zero, indicates that stack traces in the logs should be
  // symbolized using provided .pdb files.
  uint32_t symbolize;

  // Specifies path to directory containing .pdb files for the kernel
  // modules of the guest system. Valid only if globals::symbolize is
  // non-zero.
  char *symbol_path;

  // Indicates if the stack/pools allocation origins should be saved.
  uint32_t track_origins;

  // Indicates if callstack-based uniquization should take place.
  uint32_t uniquize;

  // Indicates if an interrupt should be generated within the guest OS if
  // an error is encountered.
  uint32_t break_on_bug;

  // Offset of the nt!KiSystemCall64 symbol within ntoskrnl.exe, used to
  // determine the kernel's base address in memory.
  uint64_t KiSystemCall64_offset;

  // Offsets of the first and last instructions of the kernel allocators.
  std::vector<uint64_t> pool_alloc_prologues;
  std::vector<uint64_t> pool_alloc_epilogues;

  // The signature of the memcpy() function prologue used by the kernel.
  std::string memcpy_signature;

  // Initialize fields with typical values for safety.
  bochspwn_config() : log_path(strdup("memlog.txt")), file_handle(NULL),
                  os_version(strdup("win7_32")), callstack_length(64),
                  symbolize(0), symbol_path(NULL), uniquize(0), break_on_bug(0),
                  KiSystemCall64_offset(0) {}

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

    if (symbol_path != NULL) {
      free(symbol_path);
    }
  }
};

// A single entry in the call stack.
struct callstack_item {
  uint64_t relative_pc;
  uint64_t module_base;
  std::string module_name;
};

// Information about a known kernel module currently loaded in the
// operating system.
struct module_info {
  uint64_t module_base;
  uint64_t module_size;
  std::string module_name;

  module_info() : module_base(0), module_size(0) {}
  module_info(bx_address b, bx_address s, std::string n) :
    module_base(b), module_size(s), module_name(n) {}
};

// ------------------------------------------------------------------
// Global helper functions.
// ------------------------------------------------------------------

// Find kernel module descriptor.
module_info *find_module(bx_address item);
module_info *find_module_by_name(const std::string& module);

// Formats string as a hex binary blob.
std::string format_hex(const std::string& data);

// Decodes a hex-encoded string.
std::string unhexlify(const std::string& data);

// Generates an interrupt exception in the guest operating system.
void invoke_guest_int3(BX_CPU_C *pcpu, bool rip_is_cur_instr, bxInstruction_c *i);

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

// Global information about all currently known kernel modules. Updated
// lazily, only when an unknown driver is encountered.
extern std::vector<module_info *> modules;

// Same as "modules", but storing references to especially frequently
// encountered modules.
extern std::vector<module_info *> special_modules;

// If known_callstack_item.find(address) != .end(), it means that the address
// has been already encountered as a part of a stack trace.
extern std::unordered_set<bx_address> known_callstack_item;

// Stores information about leaked allocation origins seen in the past.
extern std::unordered_set<bx_address> known_origin;

// Base address of ntoskrnl.exe optimized for quick access.
extern bx_address nt_base;

// Indicates if a specific address was determined to be an instance of memcpy().
extern std::unordered_map<bx_address, bool> is_address_memcpy;

// Indicates if a specific value of RSP belongs to a thread that currently
// executes the memcpy() function. This is used to ignore all writes within such
// function.
extern std::unordered_set<bx_address> rsp_locked;

// Large helper allocations filled with the pool/stack taint bytes (both of size
// kTaintHelperAllocSize).
extern uint8_t *pool_taint_alloc;
extern uint8_t *stack_taint_alloc;

// Information about pending requested pool allocations per stack pointer, as
// captured by the allocator prologue hook.
struct alloc_request {
  uint64_t size;
  uint64_t origin;
};
extern std::unordered_map<uint64_t, alloc_request> pending_allocs;

// An instruction-scope marker (set by before_execution, unset by
// after_execution) indicating if the current instruction (handled by
// lin_access) is a member of the REP MOVSx family, in which case it is
// handled in a special way.
extern bool rep_movs;

// An instruction-scope marker indicating if the current instruction is one of
// the rsp-modifying ones.
extern bool rsp_change;

// If rsp is being modified by the current instruction, this variable
// stores its original value from before its execution.
extern uint64_t rsp_value;

// Stores information on whether a custom breakpoint was installed by the
// instrumentation (in order to break into kernel debugger), and the location
// that was modified in order to insert it.
extern bool bp_active;
extern uint64_t bp_address;
extern uint8_t bp_orig_byte;

}  // namespace globals

#endif  // BOCHSPWN_COMMON_H_


