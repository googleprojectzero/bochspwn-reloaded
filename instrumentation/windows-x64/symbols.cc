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

#include "symbols.h"

#include "DbgHelp.h"

#include <stdint.h>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <unordered_map>

#include "common.h"
#include "os_windows.h"

namespace symbols {

std::unordered_map<std::string, driver_sym *> known_modules;

bool add_module(const std::string& module) {
  static char pdb_path[256];
  snprintf(pdb_path, sizeof(pdb_path), "%s\\%s.pdb", globals::config.symbol_path,
           strip_ext(module).c_str());

  uint64_t module_base;
  uint32_t module_size;
  if (!get_file_params(module, &module_base, &module_size)) {
    fprintf(stderr, "Unable to find \"%s\" debug file\n", pdb_path);
    known_modules[module] = new driver_sym(0, 0);
    return false;
  }

  uint64_t pdb_base = SymLoadModule64(GetCurrentProcess(), NULL, pdb_path, NULL, module_base, module_size);
  if (!pdb_base) {
    fprintf(stderr, "SymLoadModule64 failed, %lu\n", GetLastError());
    known_modules[module] = new driver_sym(0, 0);
    return false;
  }

  known_modules[module] = new driver_sym(pdb_base, module_base);
  return true;
}

std::string symbolize_address(uint64_t address) {
  module_info *mi = find_module(address);
  if (mi == NULL) {
    mi = windows::update_module_list(BX_CPU_THIS, address);
  }

  if (mi == NULL) {
    char buffer[32];
    snprintf(buffer, sizeof(buffer), "%llx", address);
    return buffer;
  }

  return symbolize_offset(mi->module_name, address - mi->module_base);
}

std::string symbolize_offset(const std::string& module, uint32_t offset) {
  static char buffer[256];
  uint64_t module_base;

  // Check if module is already loaded.
  std::unordered_map<std::string, driver_sym *>::iterator it = known_modules.find(module);
  if (it == known_modules.end()) {
    if (add_module(module)) {
      it = known_modules.find(module);
    }
  }

  if (it == known_modules.end() || it->second->pdb_base == 0) {
    snprintf(buffer, sizeof(buffer), "%s+%x", module.c_str(), offset);
    return std::string(buffer);
  } else {
    module_base = it->second->module_base;
  }

  symbol_info_package sip;
  uint64_t displacement = 0;

  if (!SymFromAddr(GetCurrentProcess(), module_base + offset, &displacement, &sip.si)) {
    snprintf(buffer, sizeof(buffer), "%s+%x", module.c_str(), offset);
  } else {
    snprintf(buffer, sizeof(buffer), "%s!%s+%.8llx", module.c_str(), sip.si.Name, displacement);
  }

  return std::string(buffer);
}

void initialize() {
  uint32_t options = SymGetOptions();
  options |= SYMOPT_DEBUG;
  SymSetOptions(options);

  if (!SymInitialize(GetCurrentProcess(), NULL, FALSE)) {
    fprintf(stderr, "SymInitialize() failed, %lu. Consider setting \"symbolize=0\" "
                    "in your configuration file.\n", GetLastError());
    abort();
  }
}

void destroy() {
  for (auto it : known_modules) {
    SymUnloadModule64(GetCurrentProcess(), it.second->pdb_base);
    delete it.second;
  }

  known_modules.clear();
}

const std::string strip_ext(const std::string file_name) {
  size_t x = file_name.find_last_of(".");
  if (x == std::string::npos) {
    return file_name;
  }

  return file_name.substr(0, x);
}

bool get_file_params(const std::string& module, uint64_t *base_address, uint32_t *module_size) {
  module_info *mi = find_module_by_name(module);
  if (mi == NULL) {
    return false;
  }

  *base_address = mi->module_base;
  *module_size = mi->module_size;
  return true;
}

}  // namespace symbols

