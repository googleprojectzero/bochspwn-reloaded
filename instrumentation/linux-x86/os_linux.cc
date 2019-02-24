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

#include "os_linux.h"

#include <cstdio>
#include <cstdlib>

#include "common.h"
#include "instrument.h"
#include "logging.pb.h"

namespace linux {

namespace config {
  uint32_t addr_modules;
  uint32_t off_module_list;
  uint32_t off_module_name;
  uint32_t off_module_base;
  uint32_t off_module_size;
  uint32_t conf_module_name_len;

  uint32_t kernel_start;
  uint32_t kernel_end;
}  // namespace config

struct module_summary_st {
  uint32_t l_prev, l_next;
  uint32_t base;
  uint32_t size;
  char name[MAX_MODULE_NAME_LEN];
};

// Helper routines.
static bool fetch_module_info(BX_CPU_C *pcpu, uint32_t module_ptr, module_summary_st *m);
static module_info *update_module_list(BX_CPU_C *pcpu, uint32_t pc);

bool init(const char *config_path) {
  char buffer[256];

  READ_INI_INT(config_path, globals::config.os_version, "modules",
               buffer, sizeof(buffer), config::addr_modules);
  READ_INI_INT(config_path, globals::config.os_version, "module_list",
               buffer, sizeof(buffer), config::off_module_list);
  READ_INI_INT(config_path, globals::config.os_version, "module_name",
               buffer, sizeof(buffer), config::off_module_name);
  READ_INI_INT(config_path, globals::config.os_version, "module_base",
               buffer, sizeof(buffer), config::off_module_base);
  READ_INI_INT(config_path, globals::config.os_version, "module_size",
               buffer, sizeof(buffer), config::off_module_size);
  READ_INI_INT(config_path, globals::config.os_version, "module_name_len",
               buffer, sizeof(buffer), config::conf_module_name_len);

  READ_INI_INT(config_path, globals::config.os_version, "kernel_start",
               buffer, sizeof(buffer), config::kernel_start);
  READ_INI_INT(config_path, globals::config.os_version, "kernel_end",
               buffer, sizeof(buffer), config::kernel_end);

  assert(config::conf_module_name_len <= MAX_MODULE_NAME_LEN);

  // Put the kernel address and size in the module list.
  module_info *mi = new module_info(
      config::kernel_start,
      config::kernel_end - config::kernel_start,
      "vmlinux");

  globals::modules.push_back(mi);

  return true;
}

bool check_kernel_addr(uint32_t addr) {
  return (addr >= 0xc0000000);
}

bool check_user_addr(uint32_t addr) {
  return (addr < 0xc0000000);
}

void fill_callstack(BX_CPU_C *pcpu, bug_report_t *bug_report) {
  // Read the stack trace.
  uint32_t ip = pcpu->prev_rip;
  uint32_t bp = pcpu->gen_reg[BX_32BIT_REG_EBP].dword.erx;
  module_info *mi = NULL;

  for (unsigned int i = 0; i < globals::config.callstack_length &&
                           linux::check_kernel_addr(ip) &&
                           linux::check_kernel_addr(bp); i++) {
    // Optimization: check last module first.
    if (mi == NULL || mi->module_base > ip || mi->module_base + mi->module_size <= ip) {
      mi = find_module(ip);
      if (mi == NULL) {
        mi = update_module_list(pcpu, ip);
      }
    }

    bug_report_t::callstack_item *new_item = bug_report->add_stack_trace();
    if (mi != NULL) {
      new_item->set_relative_pc(ip - mi->module_base);
      new_item->set_module_base(mi->module_base);
      new_item->set_module_name(mi->module_name);
    } else {
      new_item->set_relative_pc(ip);
      new_item->set_module_base(0);
      new_item->set_module_name("unknown");
    }

    if (!bp ||
        !read_lin_mem(pcpu, bp + 4, sizeof(ip), &ip) ||
        !read_lin_mem(pcpu, bp, sizeof(bp), &bp)) {
      break;
    }
  }
}

// Traverse the kernel module list to get the information about the
// driver that the "pc" is in.
static module_info *update_module_list(BX_CPU_C *pcpu, uint32_t pc) {
  // Get the address of the beginning of the list.
  uint32_t modules_start;
  if (!read_lin_mem(pcpu, config::addr_modules, sizeof(modules_start), &modules_start) ||
      modules_start == config::addr_modules) {
    // It may be not yet loaded.
    return NULL;
  }

  // Traverse the list.
  uint32_t pm = modules_start;
  for (;;) {
    // Fetch the module info.
    module_summary_st m;
    bool ret = fetch_module_info(pcpu, pm, &m);
    if (!ret) {
      break;
    }

    // Is this it?
    if (pc >= m.base && pc < m.base + m.size) {
      // Yes. We found it!
      module_info *mi = new module_info(m.base, m.size, m.name);
      globals::modules.push_back(mi);
      return mi;
    }

    // Iterate.
    // TODO(gynvael): Check the actual terminator.
    pm = m.l_next;
    if (pm == config::addr_modules || pm == 0 || pm == modules_start) {
      break;
    }
  }

  // Not found.
  return NULL;
}

// Note: This expects module_ptr to be passed without offset correction.
//       The correction will be made in this function.
static bool fetch_module_info(BX_CPU_C *pcpu, uint32_t module_ptr, module_summary_st *m) {
  // Correct offset.
  module_ptr -= config::off_module_list;
  if (!check_kernel_addr(module_ptr)) {
    return false;
  }

  // Clear the summary.
  memset(m, 0, sizeof(module_summary_st));

  // Try to fetch name.
  if (!read_lin_mem(pcpu, module_ptr + config::off_module_name,
                    config::conf_module_name_len, m->name)) {
    return false;
  }

  // Fetch list pointers in one read.
  uint32_t list[2];
  if (!read_lin_mem(pcpu, module_ptr + config::off_module_list, sizeof(list), list)) {
    return false;
  }

  m->l_next = list[0];
  m->l_prev = list[1];

  // Check sanity of these pointers. If they are not sane, something's wrong.
  if (!check_kernel_addr(m->l_next) || !check_kernel_addr(m->l_prev)) {
    return false;
  }

  // Get module address and size in the kernel memory space.
  if (!read_lin_mem(pcpu, module_ptr + config::off_module_base, 4, &m->base) ||
      !read_lin_mem(pcpu, module_ptr + config::off_module_size, 4, &m->size)) {
    return false;
  }

  // Check sanity of both core address and size.
  if (!check_kernel_addr(m->base) || m->size > MAX_MODULE_SIZE) {
    return false;
  }

  return true;
}

}  // namespace linux

