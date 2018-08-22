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

#ifndef BOCHSPWN_OS_LINUX_H_
#define BOCHSPWN_OS_LINUX_H_

#include <stdint.h>

#include "common.h"
#include "logging.pb.h"

#ifndef MAX_MODULE_NAME_LEN
#  define MAX_MODULE_NAME_LEN 256
#endif

#ifndef MAX_MODULE_SIZE
// 2MB to be safe, but this is quite excessive anyway.
#  define MAX_MODULE_SIZE (2 * 1024 * 1024)
#endif

namespace linux {

// ------------------------------------------------------------------
// System events public interface.
// ------------------------------------------------------------------
bool init(const char *);
bool check_kernel_addr(uint32_t);
bool check_user_addr(uint32_t);
void fill_callstack(BX_CPU_C *, bug_report_t *);

}  // namespace linux

#endif  // BOCHSPWN_OS_LINUX_H_

