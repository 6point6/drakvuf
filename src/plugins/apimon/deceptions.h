/*****************************************************************************
 * Splits out the new deception code from the rest of apimon with the        *
 * intention of making this a little easier to read and maintain - if we can *
 * leave apimon alone then that's one fewer thing to break! There's also the *
 * advantage that we may not only be reliant on apimon going forward so this *
 * should make any future refactor easier too.                               * 
 *****************************************************************************/

#ifndef DECEPTIONS_H
#define DECEPTIONS_H

#include <vector>
#include "apimon.h"
#include <libvmi/libvmi.h>
#include "deception_types.h"
#include "intelgathering.h"

#include "deceptions/bcrypt_decrypt.h"
#include "deceptions/create_tool_help_32_snapshot.h"
#include "deceptions/filter_find.h"
#include "deceptions/find_first_or_next_file_a.h"
#include "deceptions/get_ip_net_table.h"
#include "deceptions/icmp_send_echo_2_ex.h"
#include "deceptions/lookup_account_sid_w.h"
#include "deceptions/net_user_get_info.h"
#include "deceptions/nt_create_file.h"
#include "deceptions/process_32_first_w.h"
#include "deceptions/ssl_decrypt_packet.h"


void deception_openprocess(
    vmi_instance_t vmi, 
    drakvuf_trap_info *info, 
    drakvuf_t drakvuf, 
    deception_plugin_config* config, 
    system_info sysinfo
);
void deception_readprocessmemory(
    vmi_instance_t vmi, 
    drakvuf_trap_info *info, 
    drakvuf_t drakvuf, 
    deception_plugin_config* config, 
    system_info sysinfo,
    std::vector<simple_user>* user_list, 
    std::vector<simple_user>* new_user_list
);
void deception_overwrite_logonsessionlist(
    vmi_instance_t vmi, 
    system_info sysinfo, 
    std::vector<simple_user>* user_list,
    std::vector<simple_user>* new_user_list
);
#endif