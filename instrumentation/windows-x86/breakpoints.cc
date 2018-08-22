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

#include "breakpoints.h"

#include <unordered_map>

namespace bp {

namespace globals {
std::unordered_map<uint32_t, int> bps;
}  // namespace globals

void add_breakpoint(uint32_t address, int type) {
  globals::bps[address] = type;
}

void remove_breakpoint(uint32_t address) {
  globals::bps.erase(address);
}

int check_breakpoint(uint32_t address) {
  auto it = globals::bps.find(address);
  if (it == globals::bps.end()) {
    return -1;
  }
  return it->second;
}

}  // namespace bp

