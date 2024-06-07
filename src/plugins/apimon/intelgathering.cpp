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
#include <stdlib.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>
#include <libvmi/libvmi.h>
#include "intelgathering.h"
#include <iterator>
#include <fstream>
#include <cstdint>

extern "C" {
  #include "libdrakvuf/win.h"
}


#define MAX_PATH 260

inline unsigned int to_uint(char ch) {
    // EDIT: multi-cast fix as per David Hammen's comment
    return static_cast<unsigned int>(static_cast<unsigned char>(ch));
}

uint64_t convertToUnsignedLong(const std::vector<uint8_t>& buffer) {
    if (buffer.size() < 4) {
        throw std::invalid_argument("Buffer size is less than 4 bytes");
    }

    // Extract 4 bytes from the vector and combine them into an unsigned long
    uint64_t result = 0;
    result |= static_cast<uint8_t>(buffer[0]) << 0;
    result |= static_cast<uint8_t>(buffer[1]) << 8;
    result |= static_cast<uint8_t>(buffer[2]) << 16;
    result |= static_cast<uint8_t>(buffer[3]) << 24;
    return result;
}

std::vector<process> list_running_processes(vmi_instance_t vmi, system_info* sysinfo, deception_plugin_config* config) {
    
    std::vector<process> process_list;
    // std::time_t time_now = std::time(nullptr);
    // //std::cout << config->last_update << " | " << time_now << "\n";
    // if (config->last_update < time_now-60)    {       // Only update once a minute
    std::cout << "Starting to list running processes." << "\n";

    addr_t list_head = 0, cur_list_entry = 0, next_list_entry = 0;
    unsigned long tasks_offset = 0, pid_offset = 0, name_offset = 0;
    addr_t current_process = 0;
    char *procname = NULL;
    vmi_pid_t pid = 0;
    status_t status = VMI_FAILURE;
    //process proc_item;

    if ( VMI_FAILURE == vmi_get_offset(vmi, "win_tasks", &tasks_offset) ) {
        std::cout << "Failed to find Win Tasks offset" << "\n";
    }
    if ( VMI_FAILURE == vmi_get_offset(vmi, "win_pname", &name_offset) ) {
        std::cout << "Failed to find Win Pname offset" << "\n";
    }
    if ( VMI_FAILURE == vmi_get_offset(vmi, "win_pid", &pid_offset) ) {
        std::cout << "Failed to find Win PID offset" << "\n";
    } 

    if (VMI_FAILURE == vmi_read_addr_ksym(vmi, "PsActiveProcessHead", &list_head)) {
        std::cout << "Failed to find PsActiveProcessHead" << "\n";
    }

    cur_list_entry = list_head;
    if (VMI_FAILURE == vmi_read_addr_va(vmi, cur_list_entry, 0, &next_list_entry)) {
        std::cout << "Failed to read next pointer at " << std::hex << cur_list_entry << "\n";
    }

    int i = 0;
    
    while (1) {

    current_process = cur_list_entry - tasks_offset;
        /* Note: the task_struct that we are looking at has a lot of
        * information.  However, the process name and id are burried
        * nice and deep.  Instead of doing something sane like mapping
        * this data to a task_struct, I'm just jumping to the location
        * with the info that I want.  This helps to make the example
        * code cleaner, if not more fragile.  In a real app, you'd
        * want to do this a little more robust :-)  See
        * include/linux/sched.h for mode details */

        /* NOTE: _EPROCESS.UniqueProcessId is a really VOID*, but is never > 32 bits,
        * so this is safe enough for x64 Windows for example purposes */
        vmi_read_32_va(vmi, current_process + pid_offset, 0, (uint32_t*)&pid);

        procname = vmi_read_str_va(vmi, current_process + name_offset, 0);

        if (!procname) {
            std::cout << "Failed to find ProcName" << "\n";
        }

        /* print out the process name */
        std::cout << "PID: " << pid << ", ProcName: " << procname << "\n";
        
        process_list.push_back(process());
        process_list[i].name = procname;
        process_list[i].pid = pid;

        if (strcmp(procname, "lsass.exe") == 0) {
            sysinfo->lsass_pid = pid;
        }

        if (procname) {
            free(procname);
            procname = NULL;
        }

        /* follow the next pointer */
        cur_list_entry = next_list_entry;
        status = vmi_read_addr_va(vmi, cur_list_entry, 0, &next_list_entry);
        if (status == VMI_FAILURE) {
            std::cout << "Failed to read next pointer in loop at " << cur_list_entry << "\n";
        }
        /* In Windows, the next pointer points to the head of list, this pointer is actually the
        * address of PsActiveProcessHead symbol, not the address of an ActiveProcessLink in
        * EPROCESS struct.
        * It means in Windows, we should stop the loop at the last element in the list, while
        * in Linux, we should stop the loop when coming back to the first element of the loop
        */
        if (next_list_entry == list_head) {
            break;
        i++;
        }
    }
    std::cout << "List of running processes complete." << "\n";

    return process_list;

}


std::vector<simple_user> list_users(drakvuf_t drakvuf, vmi_instance_t vmi, system_info* sysinfo) {
    std::vector<simple_user> user_list;
    status_t status;

    addr_t lsass_eproc_addr = 0;
    bool success = win_find_eprocess(drakvuf, sysinfo->lsass_pid, "lsass.exe", &lsass_eproc_addr);
    if(!success){
        std::cout << "Unable to find Lsass.exe _EPROCESS" << "\n";
    }

    // std::cout << "Lsass.exe _EPROCESS found at: 0x" << std::hex << lsass_eproc_addr << "\n";

    addr_t modulelist_addr = 0;
    success = win_get_module_list(drakvuf, lsass_eproc_addr, &modulelist_addr);
    if(!success){
        std::cout << "Unable to find Lsass.exe Module List" << "\n";
    }

    // std::cout << "Lsass.exe Module list found at: 0x" << std::hex << modulelist_addr << "\n";

    addr_t lsass_dtb = 0;
    status = vmi_pid_to_dtb(vmi, sysinfo->lsass_pid, &lsass_dtb);
    if(status == VMI_FAILURE){
        std::cout << "Unable to translate Lsass PID to DTB" << "\n";
    }

    // std::cout << "Lsass.exe DTB is: 0x" << std::hex << lsass_dtb << "\n";

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = lsass_dtb,
    );

    module_info_t* lsasrv_info;
    lsasrv_info = win_get_module_info_ctx(drakvuf, modulelist_addr, &ctx, "lsasrv.dll");

    if(!lsasrv_info){
        std::cout << "Unable to get module info for lsasrv.dll" << "\n";
    }
    std::cout << "lsasrv.dll Base Address: 0x" << std::hex << lsasrv_info->base_addr << "\n";
    std::cout << "lsasrv.dll size: " << std::hex << lsasrv_info->size << "\n";

    ctx.addr = lsasrv_info->base_addr;
    ctx.dtb = lsass_dtb;

    std::vector<uint8_t> dll_buffer;
    addr_t chunk_position;
    addr_t increment = 0x1000;

    uint8_t buffer[increment];
    size_t bytes_read; 

    chunk_position = lsasrv_info->base_addr;
    std::cout << "Starting to download lsasrv.dll..." << "\n";
    while (chunk_position < (lsasrv_info->base_addr+lsasrv_info->size)) {
        if(VMI_SUCCESS == vmi_read_va(vmi, chunk_position, sysinfo->lsass_pid, increment, &buffer, &bytes_read))
        {
            dll_buffer.insert(dll_buffer.end(), buffer, buffer + bytes_read);
            chunk_position += increment;
        } else 
        {
            std::cout << "Unable to read lsasrv.dll increment at " << std::hex << chunk_position << ". Injecting page fault and retrying..." "\n";
            success = vmi_request_page_fault(vmi, 0, chunk_position, 0);
            if(VMI_SUCCESS == vmi_read_va(vmi, chunk_position, sysinfo->lsass_pid, increment, &buffer, &bytes_read))
            {
                dll_buffer.insert(dll_buffer.end(), buffer, buffer + bytes_read);
                chunk_position += increment;
            } else {
                std::cout << "Bytes Read: " << bytes_read << "\n";
                chunk_position = lsasrv_info->base_addr+1;
                break;
            }

        }

    }
    
    std::cout << "Lsasrv.dll download completed." << "\n";
    
    // std::cout << "Bytes Read: " << bytes_read << "\n";

    uint8_t signature[] = {0x33, 0xff, 0x41, 0x89, 0x37, 0x4c, 0x8b, 0xf3, 0x45, 0x85, 0xc0, 0x74};

    auto it = std::search(dll_buffer.begin(), dll_buffer.end(), signature, signature + sizeof(signature));

    if (it == dll_buffer.end())
    {
        std::cout << "Unable to find signature." << "\n";
    }
    else
    {
        size_t n = std::distance(dll_buffer.begin(), it);
        // std::cout << "Signature identified at position: " << n << "\n";
        // std::cout << "Translates to memory position: 0x" << std::hex << lsasrv_info->base_addr + n << "\n";
        // std::cout << "RIP Offset is at 0x" << std::hex << lsasrv_info->base_addr + n + 23 << "\n";
        // std::cout << "RIP value 0x" << std::hex << lsasrv_info->base_addr + n + 23 + 4 << "\n";
        
        std::vector<uint8_t> rip_offset_vec(4);
        std::copy(dll_buffer.begin() + n + 23, dll_buffer.begin() + n + 23 + 4, rip_offset_vec.begin());

        uint64_t rip_offset = convertToUnsignedLong(rip_offset_vec);

        addr_t log_sess_list_addr = 0;
        log_sess_list_addr = lsasrv_info->base_addr + n + 23 + 4 + rip_offset;
        std::cout << "Logon Session List can be found at: 0x" << std::hex << log_sess_list_addr << "\n";

        std::cout << "Starting to list user sessions..." << "\n";

        addr_t list_head = 0, cur_list_entry = 0, next_list_entry = 0;

        if (VMI_FAILURE == vmi_read_addr_va(vmi, log_sess_list_addr, sysinfo->lsass_pid, &cur_list_entry)) {
            std::cout << "Failed to read first pointer at 0x" << std::hex << log_sess_list_addr << "\n";
            // std::cout << "Injecting page fault at 0x" << std::hex << log_sess_list_addr << "\n";
            // success = vmi_request_page_fault (vmi, 0, log_sess_list_addr, 0);
            // drakvuf_resume(drakvuf);
            // sleep(1);
            // drakvuf_pause(drakvuf);

            if (VMI_FAILURE == vmi_read_addr_va(vmi, log_sess_list_addr, sysinfo->lsass_pid, &cur_list_entry)) {
                std::cout << "Failed to read first pointer after page fault: 0x " << std::hex << log_sess_list_addr << "\n";
                return user_list;
            }    
        }

        list_head = log_sess_list_addr;
        std::cout << "First List Address: 0x" << std::hex << cur_list_entry << "\n";

        bool keep_reading = true;
        std::cout << "Attempting to find users..." << "\n";
        while (keep_reading) {        
            try {
                if(VMI_FAILURE == vmi_read_addr_va(vmi, cur_list_entry, sysinfo->lsass_pid, &next_list_entry)) 
                {
                    std::cout << "Injecting page fault at 0x" << std::hex << cur_list_entry << "\n";
                    success = vmi_request_page_fault(vmi, 0, cur_list_entry, 0);
                    if(VMI_FAILURE == vmi_read_addr_va(vmi, cur_list_entry, sysinfo->lsass_pid, &next_list_entry)) {
                        std::cout << "Unable to read address 0x" << std::hex << cur_list_entry << "\n";
                        throw(cur_list_entry);
                    }
                }

                unicode_string_t* username_ustr = vmi_read_unicode_str_va(vmi, cur_list_entry+0x90, sysinfo->lsass_pid);
                std::string username = convert_ustr_to_string(username_ustr);
                vmi_free_unicode_str(username_ustr);

                unicode_string_t* domain_ustr = vmi_read_unicode_str_va(vmi, cur_list_entry+0xa0, sysinfo->lsass_pid);
                std::string domain = convert_ustr_to_string(domain_ustr);
                vmi_free_unicode_str(domain_ustr);

                unicode_string_t* type_ustr = vmi_read_unicode_str_va(vmi, cur_list_entry+0xc0, sysinfo->lsass_pid);
                std::string type = convert_ustr_to_string(type_ustr);
                vmi_free_unicode_str(type_ustr);

                unicode_string_t* logonsvr_ustr = vmi_read_unicode_str_va(vmi, cur_list_entry+0xf0, sysinfo->lsass_pid);
                std::string logonsvr = convert_ustr_to_string(logonsvr_ustr);
                vmi_free_unicode_str(logonsvr_ustr);
                
                std::cout << "Identified User: " << domain << "\\\\" << username << "\n";
                std::cout << "Next Pointer: 0x" << std::hex << next_list_entry << "\n";

                simple_user user;

                success = vmi_read_64_va(vmi, cur_list_entry+0xd8, sysinfo->lsass_pid, &user.logon_type);
                success = vmi_read_64_va(vmi, cur_list_entry+0xe8, sysinfo->lsass_pid, &user.session);
                success = vmi_read_16_va(vmi, cur_list_entry+0x92, sysinfo->lsass_pid, &user.max_user_len);
                success = vmi_read_16_va(vmi, cur_list_entry+0xa2, sysinfo->lsass_pid, &user.max_domain_len);
                success = vmi_read_16_va(vmi, cur_list_entry+0xf2, sysinfo->lsass_pid, &user.max_logsvr_len);

                user.pstruct_addr = cur_list_entry;
                user.user_name = username;
                user.domain = domain;
                user.logon_server = logonsvr;
                user.pcredential_blob = cur_list_entry + 0xd0;
                user.type = type;

                user_list.push_back(user);

                }
            catch (addr_t address) {
                std::cout << "Unable to read 0x" << std::hex << address << "\n";
                keep_reading = false;
                break;
                }

            if(list_head == next_list_entry) {
                keep_reading = false;
            } else {
                cur_list_entry = next_list_entry;
            }

            }

        std::cout << "List of users complete." << "\n";
    }   
    return user_list;
}