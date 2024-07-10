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

<<<<<<< HEAD
struct  deception_config {
        bool enabled;                                   // Is the function turned on?
        bool active;                                    // Has the function been called and has a leftover effect?
        uint64_t overwritten_instruction;               // Example parameter to persist data over callbacks
        addr_t overwrite_address;                       // Overwrite location
    };

struct deception_plugin_config {
     deception_config rtladjustprivilege;
     deception_config ntcreatefile;
};

typedef struct deception_plugin_config* deception_plugin_config_t;


void deception_nt_create_file(drakvuf_t drakvuf, vmi_instance_t vmi, drakvuf_trap_info* info, std::string file_to_protect);
void deception_net_user_get_info(vmi_instance_t vmi, drakvuf_trap_info* info);
void deception_net_user_enum(vmi_instance_t vmi, drakvuf_trap_info* info, drakvuf_t drakvuf, std::string targetUser);
void deception_net_query_display_info(vmi_instance_t vmi, drakvuf_trap_info* info, drakvuf_t drakvuf);
//void deception_net_lgrp_getmem(vmi_instance_t vmi, drakvuf_trap_info* info);
//void deception_lookup_account_sidw(vmi_instance_t vmi, drakvuf_trap_info* info);
void deception_icmp_send_echo_2_ex(drakvuf_t drakvuf, drakvuf_trap_info* info);
void deception_ssl_decrypt_packet(vmi_instance_t vmi, drakvuf_trap_info* info, drakvuf_t drakvuf);
void deception_find_first_or_next_file_a(vmi_instance_t vmi, drakvuf_trap_info* info, uint8_t* fake_filename);
void deception_bcrypt_decrypt(vmi_instance_t vmi, drakvuf_t drakvuf, drakvuf_trap_info* info, deception_plugin_config* config);
void deception_create_tool_help_32_snapshot(vmi_instance_t vmi, drakvuf_trap_info* info, drakvuf_t drakvuf);
void deception_process_32_first_w(vmi_instance_t vmi, drakvuf_trap_info* info, drakvuf_t drakvuf);
void deception_filter_find(vmi_instance_t vmi, drakvuf_trap_info* info, drakvuf_t drakvuf);

=======
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
>>>>>>> origin/main
#endif