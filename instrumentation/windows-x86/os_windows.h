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

#ifndef BOCHSPWN_OS_WINDOWS_H_
#define BOCHSPWN_OS_WINDOWS_H_

#include <stdint.h>

#include "common.h"
#include "logging.pb.h"

namespace windows {

// ------------------------------------------------------------------
// System events public interface.
// ------------------------------------------------------------------
bool init(const char *);
bool fill_info(BX_CPU_C *, bug_report_t *);

bool inline check_kernel_addr(uint32_t addr) {
  return (addr >= 0x80000000);
}

bool inline check_user_addr(uint32_t addr) {
  return (addr < 0x7e000000);
}

// ------------------------------------------------------------------
// Helper routines.
// ------------------------------------------------------------------
module_info *update_module_list(BX_CPU_C *pcpu, bx_address pc);

// ------------------------------------------------------------------
// Windows-specific offsets and information.
// ------------------------------------------------------------------
extern uint32_t off_kprcb;            // in KPCR
extern uint32_t off_current_thread;   // in KPRCB
extern uint32_t off_tcb;              // in ETHREAD
extern uint32_t off_process;          // in TCB
extern uint32_t off_client_id;        // in ETHREAD
extern uint32_t off_process_id;       // in CLIENT_ID
extern uint32_t off_thread_id;        // in CLIENT_ID
extern uint32_t off_create_time;      // in ETHREAD
extern uint32_t off_image_filename;   // in EPROCESS
extern uint32_t off_loadorder_flink;  // in LDR_MODULE
extern uint32_t off_basedllname;      // in LDR_MODULE
extern uint32_t off_baseaddress;      // in LDR_MODULE
extern uint32_t off_sizeofimage;      // in LDR_MODULE
extern uint32_t off_us_len;           // in UNICODE_STRING
extern uint32_t off_us_buffer;        // in UNICODE_STRING
extern uint32_t off_psloadedmodulelist; // in DBGKD_GET_VERSION64
extern uint32_t off_kdversionblock;   // in KPCR

}  // namespace windows

#endif  // BOCHSPWN_OS_WINDOWS_H_

