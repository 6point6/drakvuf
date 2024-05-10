/ @brief 
/// @param drakvuf 
/// @param vmi 
/// @param info 
void deception_rtladjustprivilege(vmi_instance_t vmi, drakvuf_t drakvuf, drakvuf_trap_info* info, deception_plugin_config* config) {
    //std::cout << "INFO    | Effect is currently active: " << config->rtladjustprivilege.active << "\n";
    // drakvuf_pause(drakvuf);  
    // ApimonReturnHookData* data = (ApimonReturnHookData*)info->trap->data;
    // std::vector<uint64_t> temp_args = data->arguments;
    // vmi_pid_t curr_pid = data->target->pid;
    // //std::vector<int> disallowed_values {2, 7, 9, 10, 20};

    // int target_luid = temp_args[0]; //RCX

    // addr_t rip_address = info->regs->rip;

    // if(vector_contains(disallowed_values, target_luid))                     // IF DISALLOWED PRIVESC
    // {



    //     std::cout << "INFO    | Disallowed PrivEsc Identified." << "\n";
    //     if(config->rtladjustprivilege.active != true)                       // IF EFFECT IS INACTIVE THEN ACTIVATE (IMPLICIT ELSE: DO NOTHING)
    //     {
    //         std::cout << "ACTION   | Finding physical address" << "\n";

    //         addr_t rip_pa;

    //         if (VMI_FAILURE == vmi_translate_uv2p(vmi, rip_address, curr_pid, &rip_pa)) 
    //         {
    //             std::cout << "ERROR   | Unable to find physical address." << "\n";
    //             return;
    //         }

    //         std::cout << "ACTION   | Persisting original instructions." << "\n";
    //         uint64_t temp_instr;
    //         if (VMI_FAILURE == vmi_read_64_pa(vmi, rip_pa, &temp_instr)) 
    //         {
    //             std::cout << "ERROR   | Unable to read instruction memory." << "\n";
    //             return;
    //         }

    //         std::cout << "INFO    | Original Instruction: 0x" << std::hex << temp_instr << "\n";

    //         std::cout << "ACTION   | Bypassing RtlAdjustPrivilege function." << "\n";
            
    //         std::vector<uint8_t> bypass_instr = {0xc3, 0x00, 0x00, 0x00, 0x00};
    //         addr_t insert_location = rip_pa;
    //         for (uint8_t byte: bypass_instr){
    //         if (VMI_FAILURE == vmi_write_8_pa(vmi, insert_location, &byte)) 
    //         {
    //             std::cout << "ERROR   | Unable to read instruction memory." << "\n";
    //             break;
    //         } 
    //         insert_location++;  
    //         } 

    //         //bool success = (VMI_SUCCESS == vmi_set_vcpureg(vmi, info->regs->rsp+0x28, RSP, info->vcpu));
    //         bool success = (VMI_SUCCESS == vmi_set_vcpureg(vmi, 0, RCX, info->vcpu));
    //         success = (VMI_SUCCESS == vmi_set_vcpureg(vmi, 0, RDX, info->vcpu));
    //         success = (VMI_SUCCESS == vmi_set_vcpureg(vmi, 0, RAX, info->vcpu));
    //         if ( !success )
    //         {
    //             PRINT_DEBUG("error while reading rsp\n");
    //             //return VMI_EVENT_RESPONSE_NONE;
    //         }

    //         std::cout << "INFO    | RtlAdjustPrivilege bypass is now ACTIVE." << "\n";

    //         config->rtladjustprivilege.overwrite_address = rip_pa;
    //         std::cout << "Saved Address: " << config->rtladjustprivilege.overwrite_address << "\n";

    //         config->rtladjustprivilege.overwritten_instruction = temp_instr;
    //         std::cout << "Saved Instructions: " << config->rtladjustprivilege.overwritten_instruction << "\n";
    //         config->rtladjustprivilege.active = true;

    //     }
    // } 
    //     else                                                            // IF ALLOWED PRIVESC 
    //     {
    //         if(config->rtladjustprivilege.active == true)               // IF EFFECT IS ACTIVE THEN DISABLE AND ROLLBACK INSTR (IMPLIED ELSE: DO NOTH)
    //         {
    //         uint64_t temp_instr;

    //         if (VMI_FAILURE == vmi_read_64_pa(  vmi, 
    //                                             config->rtladjustprivilege.overwrite_address, 
    //                                             &temp_instr)) 
    //         {
    //             std::cout << "ERROR   | Unable to read instruction memory (1)." << "\n";
    //             return;
    //         }

    //         std::cout << "INFO    | Previously Replaced Instructions: 0x" << std::hex << temp_instr << "\n";          
            
    //         std::cout << "ACTION  | Writing back original instructions" << "\n";

    //         if (VMI_FAILURE == vmi_write_64_pa( vmi, 
    //                                             config->rtladjustprivilege.overwrite_address, 
    //                                             &config->rtladjustprivilege.overwritten_instruction)) 
    //         {
    //             std::cout << "ERROR   | Unable to write instruction memory." << "\n";
    //             return;
    //         }

    //         if (VMI_FAILURE == vmi_read_64_pa(vmi, config->rtladjustprivilege.overwrite_address, &temp_instr)) 
    //         {
    //             std::cout << "ERROR   | Unable to read instruction memory. (2)" << "\n";
    //             return;
    //         }

    //         std::cout << "INFO    | Restored Instructions: 0x" << std::hex << temp_instr << "\n";
 
    //         std::cout << "INFO    | RtlAdjustPrivilege bypass is now INACTIVE." << "\n";
            
    //         config->rtladjustprivilege.active = false;
    //         config->rtladjustprivilege.overwrite_address = 0;
    //         config->rtladjustprivilege.overwritten_instruction = 0;
    //         }
        // }

    // drakvuf_resume(drakvuf);  
}

void deception_clear_eventlog(vmi_instance_t vmi, drakvuf_t drakvuf, drakvuf_trap_info* info) {

    drakvuf_pause(drakvuf);  
    ApimonReturnHookData* data = (ApimonReturnHookData*)info->trap->data;
    std::vector<uint64_t> temp_args = data->arguments; 
    vmi_pid_t curr_pid = info->attached_proc_data.pid; 

    char* log_to_clear = vmi_read_str_va(vmi, temp_args[1]+0x40, curr_pid);
    std::cout << "Log to clear: " << log_to_clear << "\n";

    drakvuf_resume(drakvuf);

}



void deception_ntadjustprivilegestoken(vmi_instance_t vmi, drakvuf_t drakvuf, drakvuf_trap_info* info, deception_plugin_config* config) {
    //
    
            // NtAdjustPrivilegesToken(
            //     _In_ HANDLE TokenHandle,
            //     _In_ BOOLEAN DisableAllPrivileges,
            //     _In_opt_ PTOKEN_PRIVILEGES NewState,  (https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_privileges)
            //     _In_ ULONG BufferLength,
            //     _Out_writes_bytes_to_opt_(BufferLength, *ReturnLength) PTOKEN_PRIVILEGES PreviousState,
            //     _Out_opt_ PULONG ReturnLength
            //     );

    //drakvuf_pause(drakvuf);

    ApimonReturnHookData* data = (ApimonReturnHookData*)info->trap->data;
    std::vector<uint64_t> temp_args = data->arguments;
    vmi_pid_t curr_pid = data->target->pid;

    addr_t ptr_tokenprivileges = temp_args[2]; // Argument 3 - R8.

    struct _luid {          //    / 8B
        uint32_t lowpart;   //32b / 4B
        uint32_t highpart;      //32b / 4B   
    };

    struct _luid_and_attributes {  // / 12B
        _luid luid;             //64b / 8B
        uint32_t attributes;    //32b / 4B
    };

    struct nt_token_privileges {
        uint32_t privilege_count;   // 32b / 4B
        _luid_and_attributes privileges; //ANYSIZE_ARRAY
    } token_privileges;

    if(VMI_FAILURE == vmi_read_32_va(vmi, ptr_tokenprivileges, curr_pid, &token_privileges.privilege_count)) {
        std::cout << "Unable to read how many privileges have been changed from memory." << "\n";
    }

    std::cout << token_privileges.privilege_count << " privileges are requested to be changed." << "\n";

    if(token_privileges.privilege_count == 1) {

        if(VMI_FAILURE == vmi_read_32_va(vmi, ptr_tokenprivileges+0x4, curr_pid, &token_privileges.privileges.luid.lowpart)) {
        std::cout << "Unable to read LUID (Low Part)." << "\n";
        }
        if(VMI_FAILURE == vmi_read_32_va(vmi, ptr_tokenprivileges+0x8, curr_pid, &token_privileges.privileges.luid.highpart)) {
        std::cout << "Unable to read LUID (High Part)." << "\n";
        }

    std::cout << "Requested Privilege LUID: " << token_privileges.privileges.luid.lowpart << "\n";

    if (token_privileges.privileges.luid.lowpart ==20) {
        
        //addr_t luid_addr = ptr_tokenprivileges+0x4;
        uint32_t new_luid = 0;

        if(VMI_FAILURE == vmi_write_32_va(vmi, ptr_tokenprivileges+0x4, curr_pid, &new_luid)) {
        std::cout << "Unable to write new LUID." << "\n";
        }
        if(VMI_FAILURE == vmi_write_32_va(vmi, ptr_tokenprivileges+0x8, curr_pid, &new_luid)) {
        std::cout << "Unable to write new attribute mask." << "\n";
        }

        uint64_t result;
        if(VMI_FAILURE == vmi_read_64_va(vmi, ptr_tokenprivileges+0x4, curr_pid, &result)) {
        std::cout << "Unable to write new attribute mask." << "\n";
        }

        std::cout << "Memory after Write " << result << "\n";
    }

    }

    //drakvuf_resume(drakvuf);
}
