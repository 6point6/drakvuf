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

#include "plugins/output_format.h"
#include "apimon.h"
#include "crypto.h" 

void dcpNtCreateFile(vmi_instance_t vmi, drakvuf_trap_info* info) {  

    // Get the data from the trap       
    ApimonReturnHookData* data = (ApimonReturnHookData*)info->trap->data;
    ApimonReturnHookData* regs = (ApimonReturnHookData*)info->regs;

    // Store all the arguments passed by the function
    std::vector<uint64_t> temp_args = data->arguments;

    //Store the values we need
    uint64_t access_mask = temp_args[1]; // Not currently using but can do something to only hit writes
    addr_t obj_attr = temp_args[2]; // This +0x10 is the UNICODE_STRING we're looking for
    vmi_pid_t curr_pid = info->attached_proc_data.pid; // Identify the malicious PID

    // Extract the target filename
    addr_t filename_addr = obj_attr + 0x10;
    unicode_string_t* target_filename = vmi_read_unicode_str_va(vmi, filename_addr, curr_pid);

    // Print the file handle requested to screen.
    std::cout << "File Handle Requested for " << target_filename->encoding << "\n"; // Remove once done debugging.

    // Catch and neutralise attempts to write to the MBR
    if (!strcmp(target_filename->encoding, "\\\\.\\PhysicalDrive0")) // FUTURE: Replace this with config lookup
    {
        std::cout << "Identified attempted MBR overwrite by PID " << curr_pid << "\n";
        
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

}


