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
/*#include "plugins/output_format.h"*/
#include "apimon.h" 
#include <string>
#include <cstring>


std::string convertToUTF8(const unicode_string_t* ustr) {
    if (strcmp(ustr->encoding, "UTF-16") == 0) {

        return std::string(reinterpret_cast<const char*>(ustr->contents), ustr->length);
    } else {
        std::cerr << "Unsupported encoding: " << ustr->encoding << "\n";
        return "";
    }
}


void dcpNtCreateFile(drakvuf_t drakvuf, drakvuf_trap_info* info) {  

    vmi_instance_t vmi = vmi_lock_guard(drakvuf);
   
    ApimonReturnHookData* data = (ApimonReturnHookData*)info->trap->data;
    std::vector<uint64_t> temp_args = data->arguments;

    //Store the values we need
    addr_t p_obj_attributes_struct = temp_args[2]; 
    vmi_pid_t curr_pid = info->attached_proc_data.pid; 
    const char* process_name = info->attached_proc_data.name;
    
    //std::cout << "NtCreateFile called by " << process_name << " (PID: " << curr_pid << ")" << "\n"; // Remove outside of debugging and demos.
    
    addr_t obj_name_ptr = p_obj_attributes_struct +0x10;

    drakvuf_pause(drakvuf);

    uint64_t obj_name_ustr_ptr = 0;

    if (VMI_FAILURE == vmi_read_64_va(vmi, obj_name_ptr, curr_pid, &obj_name_ustr_ptr))
        {
            std::cout << "Unable to read from Object Attributes." << "\n";
        }
    
    unicode_string_t* target_filename_ustr = vmi_read_unicode_str_va(vmi, (addr_t)obj_name_ustr_ptr, curr_pid);

    std::string target_filename;

    if (target_filename_ustr != NULL) 
    {
        target_filename = convertToUTF8(target_filename_ustr);
    }
    else 
    {
        target_filename = "";   
    }

    //std::cout << "File Handle Requested for " << target_filename << "\n"; // Enable for demos only.

    const char* mbr_path = "\\\\.\\PhysicalDrive0";

    //std::cout << "target_filename: " << target_filename << ". mbr_path: " << mbr_path << "\n";
    
    // Catch and neutralise attempts to write to the MBR
    if (target_filename == mbr_path) // FUTURE: Replace this with config lookup
    {
        std::cout << "WARNING!! Attempted MBR overwrite by " << process_name << " (PID: " << curr_pid << ")" << "\n";
        
        unsigned long target_vcpu = info->vcpu;

        if (VMI_FAILURE == vmi_set_vcpureg (vmi, 0, RDX, target_vcpu))
        {
            std::cout << "Unable to overwrite vCPU register. \n";
        } 
        else 
        {
            std::cout << "MBR Access Prevented. " << "\n";
        }
    }

    drakvuf_resume(drakvuf);

}


