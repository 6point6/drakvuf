#include <libvmi/libvmi.h>
#include "../apimon.h"
#include <iostream>
#include "../deception_utils.h"

/// @brief Hooks ntdll.dll!NtCreateFile and evaluates the target file object, blocking access if it is a specified file. 
/// This currently is achieved by overwriting the RSP register, resulting a crash of the calling process.
/// @param drakvuf
/// @param vmi  
/// @param info 
void deception_nt_create_file(drakvuf_t drakvuf, vmi_instance_t vmi, drakvuf_trap_info* info, std::string file_to_protect) {  

    ApimonReturnHookData* data = (ApimonReturnHookData*)info->trap->data;
    std::vector<uint64_t> temp_args = data->arguments;
    uint32_t access_mask = temp_args[1];

    if (has_any_flag(access_mask, (enum_mask_value_file)( //Query this first as we can do it without any other VMI lookups.
            (int)enum_mask_value_file::GENERIC_WRITE | 
            (int)enum_mask_value_file::GENERIC_ALL | 
            (int)enum_mask_value_file::FILE_APPEND_DATA |
            (int)enum_mask_value_file::FILE_WRITE_DATA |
            (int)enum_mask_value_file::DELETE | 
            (int)enum_mask_value_file::MAXIMUM_ALLOWED  ))) 
    {
        addr_t p_obj_attributes_struct = temp_args[2]; 
        vmi_pid_t curr_pid = info->attached_proc_data.pid; 
        const char* process_name = info->attached_proc_data.name;

        //std::cout << "INFO      | NtCreateFile with WRITE/DELETE called by " << process_name << " (PID: " << std::dec << curr_pid << ")" << "\n";

        addr_t obj_name_ptr = p_obj_attributes_struct +0x10;
        uint64_t obj_name_ustr_ptr = 0;         //Receiving variable for the response from the memory read below.

        if (VMI_FAILURE == vmi_read_64_va(vmi, obj_name_ptr, curr_pid, &obj_name_ustr_ptr))
            {
                std::cout << "ERROR     | Unable to read from Object Attributes." << "\n";
            }
        
        unicode_string_t* target_filename_ustr = vmi_read_unicode_str_va(vmi, (addr_t)obj_name_ustr_ptr, curr_pid);
        std::string target_filename = convert_ustr_to_string(target_filename_ustr); 
 
        std::vector<uint8_t> file_to_protect_array = {};
        
        for(char ch : file_to_protect){        // This loop and subsequent step converts our normal string to UCS2 in line with how Windows presents the filename in memory.
            file_to_protect_array.push_back(ch);
            file_to_protect_array.push_back(0);
        }
        std::string w_file_to_protect(file_to_protect_array.begin(), file_to_protect_array.end());
        
        std::cout << "File to Protect: " << file_to_protect << "\n";
        std::cout << "INFO      | WRITE/DELETE to " << target_filename << " identified by " << process_name << " (PID: " << std::dec << curr_pid << ")" << "\n";

        // Catch and neutralise attempts to write to the target file (or MBR if we set this to \\??\\.\\PhysicalDrive0)
        if (target_filename == w_file_to_protect) // FUTURE: Replace this with config lookup
        {
            //std::cout << "INFO      | Access to " << target_filename << " identified by " << process_name << " (PID: " << std::dec << curr_pid << ")" << "\n";
            //std::cout << "Requested Access Mask is: " << std::bitset<32>(temp_args[1]) <<"\n";

            if (VMI_FAILURE == vmi_set_vcpureg(vmi, 0x0, RSP, info->vcpu))
            {
                std::cout << "ERROR     | Unable to overwrite vCPU register. \n";
            } 
            else 
            {
                std::cout << "ACTION    | File Handle request disrupted - RSP overwritten." << "\n";
            }
        }

    }
    
}