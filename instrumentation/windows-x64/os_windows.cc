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

#include "os_windows.h"

#include <windows.h>

#include <stdint.h>

#include "common.h"
#include "logging.pb.h"
#include "mem_interface.h"
#include "symbols.h"

namespace windows {

// ------------------------------------------------------------------
// Configuration data, for detailed information see os_windows.h.
// ------------------------------------------------------------------
uint32_t off_kprcb;
uint32_t off_current_thread;
uint32_t off_tcb;
uint32_t off_process;
uint32_t off_client_id;
uint32_t off_process_id;
uint32_t off_thread_id;
uint32_t off_image_filename;
uint32_t off_loadorder_flink;
uint32_t off_basedllname;
uint32_t off_baseaddress;
uint32_t off_sizeofimage;
uint32_t off_us_len;
uint32_t off_us_buffer;
uint32_t off_psloadedmodulelist;

// ------------------------------------------------------------------
// Public Windows-specific interface.
// ------------------------------------------------------------------

bool init(const char *config_path) {
  char buffer[256];

  // Read generic Windows-specific configuration.
  READ_INI_INT(config_path, globals::config.os_version, "kprcb",
               buffer, sizeof(buffer), &off_kprcb);
  READ_INI_INT(config_path, globals::config.os_version, "current_thread",
               buffer, sizeof(buffer), &off_current_thread);
  READ_INI_INT(config_path, globals::config.os_version, "tcb",
               buffer, sizeof(buffer), &off_tcb);
  READ_INI_INT(config_path, globals::config.os_version, "process",
               buffer, sizeof(buffer), &off_process);
  READ_INI_INT(config_path, globals::config.os_version, "client_id",
               buffer, sizeof(buffer), &off_client_id);
  READ_INI_INT(config_path, globals::config.os_version, "process_id",
               buffer, sizeof(buffer), &off_process_id);
  READ_INI_INT(config_path, globals::config.os_version, "thread_id",
               buffer, sizeof(buffer), &off_thread_id);
  READ_INI_INT(config_path, globals::config.os_version, "image_filename",
               buffer, sizeof(buffer), &off_image_filename);
  READ_INI_INT(config_path, globals::config.os_version, "loadorder_flink",
               buffer, sizeof(buffer), &off_loadorder_flink);
  READ_INI_INT(config_path, globals::config.os_version, "basedllname",
               buffer, sizeof(buffer), &off_basedllname);
  READ_INI_INT(config_path, globals::config.os_version, "baseaddress",
               buffer, sizeof(buffer), &off_baseaddress);
  READ_INI_INT(config_path, globals::config.os_version, "sizeofimage",
               buffer, sizeof(buffer), &off_sizeofimage);
  READ_INI_INT(config_path, globals::config.os_version, "us_len",
               buffer, sizeof(buffer), &off_us_len);
  READ_INI_INT(config_path, globals::config.os_version, "us_buffer",
               buffer, sizeof(buffer), &off_us_buffer);
  READ_INI_INT(config_path, globals::config.os_version, "psloadedmodulelist",
               buffer, sizeof(buffer), &off_psloadedmodulelist);

  return true;
}

BOOL CALLBACK ReadProcessMemoryProc64(
  _In_  HANDLE  hProcess,
  _In_  DWORD64 lpBaseAddress,
  _Out_ PVOID   lpBuffer,
  _In_  DWORD   nSize,
  _Out_ LPDWORD lpNumberOfBytesRead
) {
  if (!read_lin_mem(BX_CPU_THIS, lpBaseAddress, nSize, lpBuffer)) {
    *lpNumberOfBytesRead = 0;
    return false;
  }

  *lpNumberOfBytesRead = nSize;
  return true;
}

void get_callstack(BX_CPU_C *pcpu, std::vector<callstack_item> *callstack) {
  uint64_t pc = pcpu->prev_rip;
  module_info *mi = NULL;

  // Initialize the current context state.
  CONTEXT ctx;
  ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS;
  ctx.EFlags = pcpu->eflags;
  ctx.Rip = pc;
  ctx.Rax = pcpu->gen_reg[BX_64BIT_REG_RAX].rrx;
  ctx.Rbx = pcpu->gen_reg[BX_64BIT_REG_RBX].rrx;
  ctx.Rcx = pcpu->gen_reg[BX_64BIT_REG_RCX].rrx;
  ctx.Rdx = pcpu->gen_reg[BX_64BIT_REG_RDX].rrx;
  ctx.Rsi = pcpu->gen_reg[BX_64BIT_REG_RSI].rrx;
  ctx.Rdi = pcpu->gen_reg[BX_64BIT_REG_RDI].rrx;
  ctx.Rbp = pcpu->gen_reg[BX_64BIT_REG_RBP].rrx;
  ctx.Rsp = pcpu->gen_reg[BX_64BIT_REG_RSP].rrx;
  ctx.R8 = pcpu->gen_reg[BX_64BIT_REG_R8].rrx;
  ctx.R9 = pcpu->gen_reg[BX_64BIT_REG_R9].rrx;
  ctx.R10 = pcpu->gen_reg[BX_64BIT_REG_R10].rrx;
  ctx.R11 = pcpu->gen_reg[BX_64BIT_REG_R11].rrx;
  ctx.R12 = pcpu->gen_reg[BX_64BIT_REG_R12].rrx;
  ctx.R13 = pcpu->gen_reg[BX_64BIT_REG_R13].rrx;
  ctx.R14 = pcpu->gen_reg[BX_64BIT_REG_R14].rrx;
  ctx.R15 = pcpu->gen_reg[BX_64BIT_REG_R15].rrx;
  ctx.SegEs = pcpu->sregs[BX_SEG_REG_ES].selector.value;
  ctx.SegCs = pcpu->sregs[BX_SEG_REG_CS].selector.value;
  ctx.SegSs = pcpu->sregs[BX_SEG_REG_SS].selector.value;
  ctx.SegDs = pcpu->sregs[BX_SEG_REG_DS].selector.value;
  ctx.SegFs = pcpu->sregs[BX_SEG_REG_FS].selector.value;
  ctx.SegGs = pcpu->sregs[BX_SEG_REG_GS].selector.value;

  // Initialize the stack frame structure.
  STACKFRAME64 sf;
  memset(&sf, 0, sizeof(sf));
  sf.AddrPC.Offset    = pc;
  sf.AddrPC.Mode      = AddrModeFlat;
  sf.AddrStack.Offset = pcpu->gen_reg[BX_64BIT_REG_RSP].rrx;
  sf.AddrStack.Mode   = AddrModeFlat;
  sf.AddrFrame.Offset = pcpu->gen_reg[BX_64BIT_REG_RBP].rrx;
  sf.AddrFrame.Mode   = AddrModeFlat;

  // Traverse the stack trace item by item.
  for (unsigned int i = 0; i < globals::config.callstack_length && check_kernel_addr(pc); i++) {
    if (!StackWalk64(IMAGE_FILE_MACHINE_AMD64,
                     /*hProcess=*/GetCurrentProcess(),
                     /*hThread=*/NULL,
                     &sf, &ctx,
                     /*ReadMemoryRoutine=*/ReadProcessMemoryProc64,
                     /*FunctionTableAccessRoutine=*/SymFunctionTableAccess64,
                     /*GetModuleBaseRoutine=*/SymGetModuleBase64,
                     /*TranslateAddress=*/NULL)) {
      break;
    }

    pc = sf.AddrPC.Offset;
    if (!check_kernel_addr(pc)) {
      break;
    }

    // Optimization: check the most recent module first.
    if (mi == NULL || mi->module_base > pc || mi->module_base + mi->module_size <= pc) {
      mi = find_module(pc);
      if (mi == NULL) {
        mi = update_module_list(pcpu, pc);
      }
    }

    callstack_item item;
    if (mi != NULL) {
      item.relative_pc = pc - mi->module_base;
      item.module_base = mi->module_base;
      item.module_name = mi->module_name;
    } else {
      item.relative_pc = pc;
      item.module_base = 0;
      item.module_name = "unknown";
    }

    callstack->push_back(item);
  }
}

// Traverse the PsLoadedModuleList linked list of drivers in search of
// one that contains the "pc" address.
module_info *update_module_list(BX_CPU_C *pcpu, bx_address pc) {
  uint64_t addr_module = 0;

  // If the nt base hasn't been determined yet, we cannot traverse the loaded
  // module list.
  if (globals::nt_base == 0) {
    return NULL;
  }

  if (!read_lin_mem(pcpu, globals::nt_base + off_psloadedmodulelist, sizeof(addr_module), &addr_module)) {
    return NULL;
  }

  // Iterate through driver information found in the kernel memory.
  uint64_t addr_module_start = addr_module;
  for (;;) {
    // Grab the base and image size.
    uint64_t base = 0;
    uint32_t imagesize = 0;
    if (!read_lin_mem(pcpu, addr_module + off_baseaddress, sizeof(base), &base) ||
        !read_lin_mem(pcpu, addr_module + off_sizeofimage, sizeof(imagesize), &imagesize)) {
      return NULL;
    }

    // If "pc" belongs to the executable, read image name and insert a
    // descriptor in global database.
    if (imagesize != 0 && pc >= base && pc < base + imagesize) {
      uint16_t unicode_length = 0;
      uint64_t unicode_buffer = 0;

      if (!read_lin_mem(pcpu, addr_module + off_basedllname + off_us_len,
                        sizeof(uint16_t), &unicode_length)) {
        return NULL;
      }

      if (!read_lin_mem(pcpu, addr_module + off_basedllname + off_us_buffer,
                        sizeof(unicode_buffer), &unicode_buffer)) {
        return NULL;
      }

      if (unicode_length == 0 || unicode_buffer == 0) {
        return NULL;
      }

      static uint16_t unicode_name[130] = {0};
      unsigned to_fetch = unicode_length;
      if (to_fetch > 254) {
        to_fetch = 254;
      }

      if (!read_lin_mem(pcpu, unicode_buffer, to_fetch, &unicode_name)) {
        return NULL;
      }

      size_t half_fetch = to_fetch / 2;  // to_fetch in unicode characters.
      static char module_name[16];
      for (unsigned i = 0; i < half_fetch && i < sizeof(module_name) - 1; i++) {
        module_name[i] = unicode_name[i];
      }
      module_name[std::min(half_fetch, sizeof(module_name) - 1)] = '\0';

      // Add to cache for future reference.
      module_info *mi = new module_info(base, imagesize, module_name);

      // ntoskrnl and win32k are the two most frequently seen drivers, so
      // put them into a prioritized list.
      if (!strcmp(module_name, "ntoskrnl.exe") || !strcmp(module_name, "win32k.sys")) {
        globals::special_modules.push_back(mi);
      } else {
        globals::modules.push_back(mi);
      }

      // Load the corresponding symbol file for the module as soon as we see it
      // for the first time here.
      symbols::add_module(mi->module_name);

      return mi;
    }

    if (!read_lin_mem(pcpu, addr_module + off_loadorder_flink, sizeof(addr_module), &addr_module) ||
        !check_kernel_addr(addr_module) ||
        addr_module - off_loadorder_flink == addr_module_start) {
      return NULL;
    }
 
    addr_module -= off_loadorder_flink;
  }

  return NULL;
}

bool fill_system_info(BX_CPU_C *pcpu, bug_report_t *report) {
  uint64_t addr_kpcr = pcpu->get_segment_base(BX_SEG_REG_GS);
  if (!check_kernel_addr(addr_kpcr)) {
    return false;
  }

  uint64_t addr_kprcb = 0;
  if (!read_lin_mem(pcpu, addr_kpcr + off_kprcb, sizeof(addr_kprcb), &addr_kprcb)) {
    return false;
  }

  uint64_t addr_ethread = 0;
  if (!read_lin_mem(pcpu, addr_kprcb + off_current_thread, sizeof(addr_ethread), &addr_ethread)) {
    return false;
  }

  uint64_t addr_clientid = addr_ethread + off_client_id;
  uint64_t pid = 0, tid = 0;
  read_lin_mem(pcpu, addr_clientid + off_process_id, sizeof(pid), &pid);
  read_lin_mem(pcpu, addr_clientid + off_thread_id, sizeof(tid), &tid);

  uint64_t addr_eprocess = 0;
  if (!read_lin_mem(pcpu, addr_ethread + off_tcb + off_process, sizeof(addr_eprocess), &addr_eprocess)) {
    return false;
  }

  static char image_file_name[16];
  if (!read_lin_mem(pcpu, addr_eprocess + off_image_filename, 15, image_file_name)) {
    return false;
  }

  report->set_process_id(pid);
  report->set_thread_id(tid);
  report->set_image_file_name(image_file_name);

  return true;
}

}  // namespace windows

