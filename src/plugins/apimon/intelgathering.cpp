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

std::vector<process> list_running_processes(drakvuf_t drakvuf, vmi_instance_t vmi, drakvuf_trap_info* info, system_info* sysinfo, deception_plugin_config* config) {
    
    std::vector<process> process_list;

    //std::cout << "Starting to list running processes." << "\n";
    log_message("DEBUG", "data_collection", "list_running_processes", "NONE", "Starting to list running processes.");

    addr_t list_head = 0, cur_list_entry = 0, next_list_entry = 0;
    unsigned long tasks_offset = 0, pid_offset = 0, name_offset = 0;
    addr_t current_process = 0;
    char *procname = NULL;
    vmi_pid_t pid = 0;
    status_t status = VMI_FAILURE;

    if ( VMI_FAILURE == vmi_get_offset(vmi, "win_tasks", &tasks_offset) ) {
        log_message("ERROR", "data_collection", "list_running_processes", "NONE", "Failed to find Win Tasks offset.");
    }
    if ( VMI_FAILURE == vmi_get_offset(vmi, "win_pname", &name_offset) ) {
        log_message("ERROR", "data_collection", "list_running_processes", "NONE", "Failed to find Win Pname offset.");
    }
    if ( VMI_FAILURE == vmi_get_offset(vmi, "win_pid", &pid_offset) ) {
        log_message("ERROR", "data_collection", "list_running_processes", "NONE", "Failed to find Win PID offset.");
    } 

    if (VMI_FAILURE == vmi_read_addr_ksym(vmi, "PsActiveProcessHead", &list_head)) {
        log_message("ERROR", "data_collection", "list_running_processes", "NONE", "Failed to find PsActiveProcessHead.");
    }

    cur_list_entry = list_head;
    if (VMI_FAILURE == vmi_read_addr_va(vmi, cur_list_entry, 0, &next_list_entry)) {
        std::ostringstream oss;
        oss << "Failed to read next pointer at " << std::hex << cur_list_entry;
        log_message("ERROR", "data_collection", "list_running_processes", "NONE", oss.str().c_str());
    }

    int i = 0;
    
    while (1) {

    current_process = cur_list_entry - tasks_offset;

        vmi_read_32_va(vmi, current_process + pid_offset, 0, (uint32_t*)&pid);

        procname = vmi_read_str_va(vmi, current_process + name_offset, 0);

        if (!procname) {
            log_message("ERROR", "data_collection", "list_running_processes", "NONE", "Failed to find ProcName.");
        }

        process proc;
        proc.flink = next_list_entry;
        vmi_read_addr_va(vmi, current_process+0x8, 0, &proc.blink);
        proc.p_addr = cur_list_entry;
        proc.name = procname;
        proc.pid = pid;

        process_list.push_back(proc);

        if (strcmp(procname, "lsass.exe") == 0) {
            sysinfo->lsass_pid = pid;
        }

        if (procname) {
            free(procname);
            procname = NULL;
        }

        cur_list_entry = next_list_entry;
        status = vmi_read_addr_va(vmi, cur_list_entry, 0, &next_list_entry);
        if (status == VMI_FAILURE) {
            std::ostringstream oss;
            oss << "Failed to read next pointer in loop at " << cur_list_entry;
            log_message("ERROR", "data_collection", "list_running_processes", "NONE", oss.str().c_str());
        }

        if (next_list_entry == list_head) {
            break;
        i++;
        }
    }

    time_t time_now = std::time(nullptr);

    for (process p: process_list) {

        std::cout << "{";
            std::cout << "\"timestamp\": "      << std::dec << time_now                         << ", "; 
            std::cout << "\"level\": "          << "\"INFO\""                        << ", ";
            std::cout << "\"type\": "           << "\"data_collection\""                        << ", ";
            std::cout << "\"event\": "          << "\"process_found\""                          << ", ";
            std::cout << "\"event_id\": "       << "\""<< std::hex << info->event_uid << "\""   << ", ";
            std::cout << "\"process_name\": "   << "\""<< p.name << "\""                        << ", ";
            std::cout << "\"pid\": "            << p.pid                                        << ", ";
            std::cout << "\"process_list_address\": "   << "\""<< std::hex << p.p_addr << "\""  << ", ";
            std::cout << "\"flink\": "   << "\""<< std::hex << p.flink << "\""                  << ", ";
            std::cout << "\"blink\": "   << "\""<< std::hex << p.blink << "\""                  ;
        std::cout << "}" << "\n";
    }

    return process_list;

}


std::vector<simple_user> list_users(drakvuf_t drakvuf, vmi_instance_t vmi, drakvuf_trap_info* info, system_info* sysinfo) {
    std::vector<simple_user> user_list;
    status_t status;

    addr_t lsass_eproc_addr = 0;
    bool success = win_find_eprocess(drakvuf, sysinfo->lsass_pid, "lsass.exe", &lsass_eproc_addr);
    if(!success){
        log_message("ERROR", "data_collection", "list_users", "NONE", "Unable to find Lsass.exe _EPROCESS");
    }

    addr_t modulelist_addr = 0;
    success = win_get_module_list(drakvuf, lsass_eproc_addr, &modulelist_addr);
    if(!success){
        log_message("ERROR", "data_collection", "list_users", "NONE", "Unable to find Lsass.exe Module List");
    }

    addr_t lsass_dtb = 0;
    status = vmi_pid_to_dtb(vmi, sysinfo->lsass_pid, &lsass_dtb);
    if(status == VMI_FAILURE){
        log_message("ERROR", "data_collection", "list_users", "NONE", "Unable to find Lsass.exe Module List");
    }

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = lsass_dtb,
    );

    module_info_t* lsasrv_info;
    lsasrv_info = win_get_module_info_ctx(drakvuf, modulelist_addr, &ctx, "lsasrv.dll");

    if(!lsasrv_info){
        log_message("ERROR", "data_collection", "list_users", "NONE", "Unable to get module info for lsasrv.dll");
    }

    ctx.addr = lsasrv_info->base_addr;
    ctx.dtb = lsass_dtb;

    std::vector<uint8_t> dll_buffer;
    addr_t chunk_position;
    addr_t increment = 0x1000;

    uint8_t buffer[increment];
    size_t bytes_read; 

    chunk_position = lsasrv_info->base_addr;
    log_message("DEBUG", "data_collection", "list_users", "NONE", "Starting to download lsasrv.dll...");
    while (chunk_position < (lsasrv_info->base_addr+lsasrv_info->size)) {
        if(VMI_SUCCESS == vmi_read_va(vmi, chunk_position, sysinfo->lsass_pid, increment, &buffer, &bytes_read))
        {
            dll_buffer.insert(dll_buffer.end(), buffer, buffer + bytes_read);
            chunk_position += increment;
        } else 
        {
            std::ostringstream oss;
            oss << "Unable to read lsasrv.dll increment at " << std::hex << chunk_position << ". Injecting page fault and retrying.";
            log_message("WARN", "data_collection", "list_users", "NONE", oss.str().c_str());
            
            success = vmi_request_page_fault(vmi, 0, chunk_position, 0);

            if(VMI_SUCCESS == vmi_read_va(vmi, chunk_position, sysinfo->lsass_pid, increment, &buffer, &bytes_read))
            {
                dll_buffer.insert(dll_buffer.end(), buffer, buffer + bytes_read);
                chunk_position += increment;
            } else {
                std::ostringstream oss;
                oss << "Still unable to read lsasrv.dll increment. Bytes Read: " << bytes_read;
                log_message("ERROR", "data_collection", "list_users", "NONE", oss.str().c_str());
                chunk_position = lsasrv_info->base_addr+lsasrv_info->size+1;
                break;
            }
        }
    }

    uint8_t signature[] = {0x33, 0xff, 0x41, 0x89, 0x37, 0x4c, 0x8b, 0xf3, 0x45, 0x85, 0xc0, 0x74}; //Mimikatz sig for Win10 19045

    auto it = std::search(dll_buffer.begin(), dll_buffer.end(), signature, signature + sizeof(signature));

    if (it == dll_buffer.end())
    {
        log_message("ERROR", "data_collection", "list_users", "NONE", "Unable to find signature.");
    }
    else
    {
        size_t n = std::distance(dll_buffer.begin(), it);
        
        std::vector<uint8_t> rip_offset_vec(4);
        std::copy(dll_buffer.begin() + n + 23, dll_buffer.begin() + n + 23 + 4, rip_offset_vec.begin());

        uint64_t rip_offset = convertToUnsignedLong(rip_offset_vec);

        addr_t log_sess_list_addr = 0;
        log_sess_list_addr = lsasrv_info->base_addr + n + 23 + 4 + rip_offset;

        addr_t list_head = 0, cur_list_entry = 0, next_list_entry = 0;

        if (VMI_FAILURE == vmi_read_addr_va(vmi, log_sess_list_addr, sysinfo->lsass_pid, &cur_list_entry)) {
            std::ostringstream oss;
            oss << "Failed to read first pointer at 0x" << std::hex << log_sess_list_addr;
            log_message("ERROR", "data_collection", "list_users", "NONE", oss.str().c_str());

            if (VMI_FAILURE == vmi_read_addr_va(vmi, log_sess_list_addr, sysinfo->lsass_pid, &cur_list_entry)) {
                std::ostringstream oss;
                oss << "Failed to read first pointer after page fault: 0x " << std::hex << log_sess_list_addr;
                log_message("ERROR", "data_collection", "list_users", "NONE", oss.str().c_str());
                return user_list;
            }    
        }

        list_head = log_sess_list_addr;

        bool keep_reading = true;

        while (keep_reading) {        
            try {
                if(VMI_FAILURE == vmi_read_addr_va(vmi, cur_list_entry, sysinfo->lsass_pid, &next_list_entry)) 
                {
                    std::ostringstream oss;
                    oss << "Unable to read user entry. Injecting page fault at 0x" << std::hex << cur_list_entry;
                    log_message("WARN", "data_collection", "list_users", "NONE", oss.str().c_str());
                    success = vmi_request_page_fault(vmi, 0, cur_list_entry, 0);
                    if(VMI_FAILURE == vmi_read_addr_va(vmi, cur_list_entry, sysinfo->lsass_pid, &next_list_entry)) {
                        
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

                simple_user user;

                success = vmi_read_addr_va(vmi, cur_list_entry, sysinfo->lsass_pid, &user.flink);
                success = vmi_read_addr_va(vmi, cur_list_entry+0x8, sysinfo->lsass_pid, &user.blink);

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
                std::ostringstream oss;
                oss << "Unable to read 0x" << std::hex << address;
                log_message("ERROR", "data_collection", "list_users", "NONE", oss.str().c_str());
                keep_reading = false;
                break;
                }

            if(list_head == next_list_entry) {
                keep_reading = false;
            } else {
                cur_list_entry = next_list_entry;
            }

            }

    }

    time_t time_now = std::time(nullptr);

    for (simple_user u: user_list) {

        std::cout << "{";
            std::cout << "\"timestamp\": "      << std::dec << time_now             << ", "; 
            std::cout << "\"type\": "           << "\"data_collection\""            << ", ";
            std::cout << "\"event\": "          << "\"user_found\""                 << ", ";
            std::cout << "\"event_id\": "       << "\""<< info->event_uid << "\""   << ", ";

            std::cout << "\"user_name\": "      << "\""<< u.user_name << "\""       << ", ";
            std::cout << "\"user_domain\": "    << "\""<< u.domain << "\""          << ", ";
            std::cout << "\"logon_server\": "   << "\""<< u.logon_server << "\""    << ", ";
            std::cout << "\"u.type\": "           << "\""<< u.type << "\""            << ", ";

            std::cout << "\"struct_addr\": "    << "\""<< std::hex << u.pstruct_addr << "\"" << ", ";
            std::cout << "\"user_name_maxlen\": "      << std::dec << u.max_user_len            << ", ";
            std::cout << "\"domain_maxlen\": "      << std::dec << u.max_domain_len             << ", ";
            std::cout << "\"logonserver_maxlen\": "      << std::dec << u.max_logsvr_len        << ", ";

            std::cout << "\"flink\": "   << "\""<< std::hex << u.flink << "\""      << ", ";
            std::cout << "\"blink\": "   << "\""<< std::hex << u.blink << "\"";

        std::cout << "}" << "\n";
    }

    return user_list;
}