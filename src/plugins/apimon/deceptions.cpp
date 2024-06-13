/*****************************************************************************
 * Splits out the new deception code from the rest of apimon with the        *
 * intention of making this a little easier to read and maintain - if we can *
 * leave apimon alone then that's one fewer thing to break! There's also the *
 * advantage that we may not only be reliant on apimon going forward so this *
 * should make any future refactor easier too.                               * 
 *****************************************************************************/


#include <iostream>
#include <stdexcept>
#include <inttypes.h>
#include <assert.h>
#include <vector>
#include <string>
#include <cstring>
#include <codecvt>
#include <locale>
#include <stdint.h>
#include "plugins/output_format.h"
#include "apimon.h" 
#include "deception_utils.h"
#include <algorithm>
#include "deceptions.h"
#include "intelgathering.h"



void deception_openprocess(vmi_instance_t vmi, drakvuf_trap_info *info, drakvuf_t drakvuf, deception_plugin_config* config, system_info sysinfo) {
    ApimonReturnHookData* data = (ApimonReturnHookData*)info->trap->data; 
    std::vector<uint64_t> temp_args = data->arguments;

    // std::vector<process> process_list;

    // if(!sysinfo.lsass_pid) {       // Handle edge-case where this runs before we have a target PID. 
    //     process_list = list_running_processes(vmi, &sysinfo, *config);
    // }

    if((int32_t)temp_args[2] == sysinfo.lsass_pid){
        std::cout << "LSASS Mememory Handle Opened. Enabling ReadProcessMemory Trap." << "\n";
        config->readprocessmemory.enabled = true;
        config->readprocessmemory.target_handle = info->regs->rax;
    }

}

void deception_readprocessmemory(vmi_instance_t vmi, drakvuf_trap_info *info, drakvuf_t drakvuf, deception_plugin_config* config, system_info sysinfo,
                                   std::vector<simple_user>* user_list, std::vector<simple_user>* new_user_list) {
    ApimonReturnHookData* data = (ApimonReturnHookData*)info->trap->data; 
    std::vector<uint64_t> temp_args = data->arguments;

    if(temp_args[0] != config->readprocessmemory.target_handle){ // We only want to act on handles reading LSASS so break for other handles.
        return;
    }

    std::cout << "DEBUG | SOURCE: 0x" << temp_args[1] << " | DEST: 0x" << temp_args[2] << " | SIZE: " << std::hex << temp_args[3] << "\n";

    if(temp_args[3] > 0x100000) {
        if (config->readprocessmemory.active != true) {
            deception_overwrite_logonsessionlist(vmi, sysinfo, user_list, new_user_list);               // Overwrite the LSL with our new values.
            config->readprocessmemory.active = true;    // Mark that we've done this so we don't do it again. 
            config->bcryptdecrypt.enabled = true;
        } 
    }
    return;
}


void deception_overwrite_logonsessionlist(vmi_instance_t vmi, system_info sysinfo, std::vector<simple_user> user_list,
                                                std::vector<simple_user> new_user_list) {

    status_t success;
    for (simple_user user: new_user_list) {
        if(user.changed ==true) {
            std::cout << "Overwriting LogonSessionList entry at position 0x" << std::hex << user.pstruct_addr;
            success = vmi_overwrite_unicode_str_va(vmi, user.pstruct_addr + 0x90, sysinfo.lsass_pid, user.user_name);
            if (success == VMI_FAILURE) {
                std::cout << "Unable to overwrite LogonSessionList." << "\n";
                break;
            }
            success = vmi_overwrite_unicode_str_va(vmi, user.pstruct_addr + 0xa0, sysinfo.lsass_pid, user.domain);
            if (success == VMI_FAILURE) {
                std::cout << "Unable to overwrite LogonSessionList." << "\n";
                break;
            }
            success = vmi_overwrite_unicode_str_va(vmi, user.pstruct_addr + 0xf0, sysinfo.lsass_pid, user.logon_server);
            if (success == VMI_FAILURE) {
                std::cout << "Unable to overwrite LogonSessionList." << "\n";
                break;
            }
            
            for (simple_user old_user: user_list) {
                if (old_user.pstruct_addr == user.pstruct_addr) {
                    old_user.changed = true;
                }
            }
        }
    } 
}