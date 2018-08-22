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
uint32_t off_us_len;
uint32_t off_us_buffer;
uint32_t off_teb_cid;
uint32_t off_psloadedmodulelist;
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

bool check_kernel_addr(uint32_t addr) {
  return (addr >= 0x80000000);
}

bool check_user_addr(uint32_t addr) {
  return (addr < 0x7e000000);
}

// ------------------------------------------------------------------
// Helper routines.
// ------------------------------------------------------------------

// Traverse the PsLoadedModuleList linked list of drivers in search of
// the ntoskrnl.exe image address.
uint32_t get_nt_kernel_address(BX_CPU_C *pcpu) {
  uint32_t addr_kpcr = pcpu->get_segment_base(BX_SEG_REG_FS);
  if (!check_kernel_addr(addr_kpcr)) {
    return 0;
  }

  uint32_t addr_dbg_block = 0;
  if (!read_lin_mem(pcpu, addr_kpcr + off_kdversionblock, sizeof(addr_dbg_block), &addr_dbg_block) ||
      !check_kernel_addr(addr_dbg_block)) {
    return 0;
  }

  uint32_t addr_module = 0;
  if (!read_lin_mem(pcpu, addr_dbg_block + off_psloadedmodulelist, sizeof(addr_module), &addr_module) ||
      !check_kernel_addr(addr_module)) {
    return 0;
  }

  uint32_t addr_module_start = addr_module;
  for (;;) {
    uint32_t base = 0;
    if (!read_lin_mem(pcpu, addr_module + off_baseaddress, sizeof(base), &base)) {
      return 0;
    }

    if (base != 0) {
      uint16_t unicode_length = 0;
      uint32_t unicode_buffer = 0;

      if (!read_lin_mem(pcpu, addr_module + off_basedllname + off_us_len,
                        sizeof(uint16_t), &unicode_length)) {
        return 0;
      }

      if (!read_lin_mem(pcpu, addr_module + off_basedllname + off_us_buffer,
                        sizeof(unicode_buffer), &unicode_buffer)) {
        return 0;
      }

      if (unicode_length == 0 || unicode_buffer == 0) {
        return 0;
      }

      static uint16_t unicode_name[130] = {0};
      unsigned to_fetch = unicode_length;
      if (to_fetch > 254) {
        to_fetch = 254;
      }

      if (!read_lin_mem(pcpu, unicode_buffer, to_fetch, &unicode_name)) {
        return 0;
      }

      size_t half_fetch = to_fetch / 2;  // to_fetch in unicode characters.
      static char module_name[16];
      for (unsigned i = 0; i < half_fetch && i < sizeof(module_name) - 1; i++) {
        module_name[i] = unicode_name[i];
      }
      module_name[std::min(half_fetch, sizeof(module_name) - 1)] = '\0';

      if (!strcmp(module_name, "ntoskrnl.exe")) {
        return base;
      }
    }

    if (!read_lin_mem(pcpu, addr_module + off_loadorder_flink, sizeof(addr_module), &addr_module) ||
        !check_kernel_addr(addr_module) ||
        addr_module - off_loadorder_flink == addr_module_start) {
      return 0;
    }

    addr_module -= off_loadorder_flink;
  }

  return 0;
}

}  // namespace windows

