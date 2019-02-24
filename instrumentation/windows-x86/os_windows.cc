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

#include <stdint.h>
#include <windows.h>

#include "common.h"
#include "instrument.h"
#include "logging.pb.h"

// ------------------------------------------------------------------
// Configuration data, for detailed information see os_windows.h.
// ------------------------------------------------------------------
namespace windows {

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
uint32_t off_teb_cid;
uint32_t off_psloadedmodulelist;
uint32_t off_irql;
uint32_t off_kdversionblock;

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
  READ_INI_INT(config_path, globals::config.os_version, "teb_cid",
               buffer, sizeof(buffer), &off_teb_cid);
  READ_INI_INT(config_path, globals::config.os_version, "psloadedmodulelist",
               buffer, sizeof(buffer), &off_psloadedmodulelist);
  READ_INI_INT(config_path, globals::config.os_version, "kdversionblock",
               buffer, sizeof(buffer), &off_kdversionblock);

  return true;
}

bool fill_info(BX_CPU_C *pcpu, bug_report_t *bug_report) {
  bx_address pc = bug_report->pc();

  // Get PCR address.
  uint32_t addr_kpcr = 0;
  addr_kpcr = pcpu->get_segment_base(BX_SEG_REG_FS);

  if (!check_kernel_addr(addr_kpcr)) {
    return false;
  }

  uint32_t addr_kprcb = addr_kpcr + off_kprcb;
  uint32_t addr_ethread = 0;
  if (!read_lin_mem(pcpu, addr_kprcb + off_current_thread, sizeof(addr_ethread), &addr_ethread)) {
    return false;
  }

  uint32_t addr_clientid = addr_ethread + off_client_id;
  uint32_t pid = 0, tid = 0;
  read_lin_mem(pcpu, addr_clientid + off_process_id, sizeof(pid), &pid);
  read_lin_mem(pcpu, addr_clientid + off_thread_id, sizeof(tid), &tid);

  uint32_t addr_eprocess = 0;
  if (!read_lin_mem(pcpu, addr_ethread + off_tcb + off_process, sizeof(addr_eprocess), &addr_eprocess)) {
    return false;
  }

  static char image_file_name[16];
  if (!read_lin_mem(pcpu, addr_eprocess + off_image_filename, 15, image_file_name)) {
    return false;
  }

  // We are not interested in smss.exe, either. It is a special process.
  if (!memcmp(image_file_name, "smss.exe", 8)) {
    return false;
  }

  bug_report->set_process_id(pid);
  bug_report->set_thread_id(tid);
  bug_report->set_image_file_name(image_file_name);

  // Read the stack trace.
  uint32_t ip = pc;
  uint32_t bp = pcpu->gen_reg[BX_32BIT_REG_EBP].dword.erx;
  module_info *mi = NULL;

  for (unsigned int i = 0; i < globals::config.callstack_length &&
                           check_kernel_addr(ip) &&
                           check_kernel_addr(bp); i++) {
    // Optimization: check last module first.
    if (!mi || mi->module_base > ip || mi->module_base + mi->module_size <= ip) {
      mi = find_module(ip);
      if (!mi) {
        mi = update_module_list(pcpu, ip);
      }
    }

    bug_report_t::callstack_item *new_item = bug_report->add_stack_trace();
    if (mi) {
      new_item->set_relative_pc(ip - mi->module_base);
      new_item->set_module_base(mi->module_base);
      new_item->set_module_name(mi->module_name);
    } else {
      new_item->set_relative_pc(pc);
      new_item->set_module_base(0);
      new_item->set_module_name("unknown");
    }

    if (!bp ||
        !read_lin_mem(pcpu, bp + 4, sizeof(ip), &ip) ||
        !read_lin_mem(pcpu, bp, sizeof(bp), &bp)) {
      break;
    }
  }

  return true;
}

// ------------------------------------------------------------------
// Helper routines.
// ------------------------------------------------------------------

// Traverse the PsLoadedModuleList linked list of drivers in search of
// one that contains the "pc" address.
module_info *update_module_list(BX_CPU_C *pcpu, bx_address pc) {
  uint32_t addr_module = 0;

  uint32_t addr_kpcr = pcpu->get_segment_base(BX_SEG_REG_FS);
  if (!check_kernel_addr(addr_kpcr)) {
    return NULL;
  }

  uint32_t addr_dbg_block = 0;
  if (!read_lin_mem(pcpu, addr_kpcr + off_kdversionblock, sizeof(addr_dbg_block), &addr_dbg_block) ||
      !check_kernel_addr(addr_dbg_block)) {
    return NULL;
  }

  if (!read_lin_mem(pcpu, addr_dbg_block + off_psloadedmodulelist, sizeof(addr_module), &addr_module) ||
      !check_kernel_addr(addr_module)) {
    return NULL;
  }

  // Iterate through driver information found in the kernel memory.
  uint32_t addr_module_start = addr_module;
  for (;;) {
    // Grab the base and image size.
    uint32_t base = 0;
    uint32_t imagesize = 0;
    if (!read_lin_mem(pcpu, addr_module + off_baseaddress, sizeof(base), &base) ||
        !read_lin_mem(pcpu, addr_module + off_sizeofimage, sizeof(imagesize), &imagesize)) {
      return NULL;
    }

    // If "pc" belongs to the executable, read image name and insert a
    // descriptor in global database.
    if (imagesize != 0 && pc >= base && pc < base + imagesize) {
      uint16_t unicode_length = 0;
      uint32_t unicode_buffer = 0;

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

}  // namespace windows

