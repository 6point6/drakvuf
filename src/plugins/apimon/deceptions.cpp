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

#define MAX_PATH 260

/// @brief Hooks ntdll.dll!NtCreateFile and evaluates the target file object, blocking access if it is a specified file. 
/// This currently is achieved by overwriting the RSP register, resulting a crash of the calling process.
/// @param drakvuf
/// @param vmi  
/// @param info 
void deception_nt_create_file(drakvuf_t drakvuf, vmi_instance_t vmi, drakvuf_trap_info* info, std::string file_to_protect) {  

    drakvuf_pause(drakvuf);         // Move this into apimon so it's consistent? 
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

        std::cout << "INFO      | NtCreateFile with WRITE/DELETE called by " << process_name << " (PID: " << std::dec << curr_pid << ")" << "\n";
        addr_t obj_name_ptr = p_obj_attributes_struct +0x10;
        uint64_t obj_name_ustr_ptr = 0;         //Receiving variable for the response from the memory read below.

        if (VMI_FAILURE == vmi_read_64_va(vmi, obj_name_ptr, curr_pid, &obj_name_ustr_ptr))
            {
                std::cout << "ERROR     | Unable to read from Object Attributes." << "\n";
            }
        
        unicode_string_t* target_filename_ustr = vmi_read_unicode_str_va(vmi, (addr_t)obj_name_ustr_ptr, curr_pid);
        std::string target_filename = convert_ustr_to_string(target_filename_ustr); 
 
        std::u16string u16_file_to_protect = convert_string_to_u16string(file_to_protect);    // Migrate from this line to before the equality check out of the loop for performance. 
        std::vector<uint8_t> file_to_protect_array = {};
        
        for(char ch : file_to_protect){        // This loop and subsequent step converts our normal string to UCS2 in line with how Windows presents the filename in memory.
            file_to_protect_array.push_back(ch);
            file_to_protect_array.push_back(0);
        }
        std::string w_file_to_protect(file_to_protect_array.begin(), file_to_protect_array.end());

        // Catch and neutralise attempts to write to the target file (or MBR if we set this to \\??\\.\\PhysicalDrive0)
        if (target_filename == w_file_to_protect) // FUTURE: Replace this with config lookup
        {
            std::cout << "INFO      | Access to " << target_filename << " identified by " << process_name << " (PID: " << std::dec << curr_pid << ")" << "\n";
            //std::cout << "Requested Access Mask is: " << std::bitset<32>(temp_args[1]) <<"\n";

            if (VMI_FAILURE == vmi_set_vcpureg (vmi, 0x0, RSP, info->vcpu))
            {
                std::cout << "ERROR     | Unable to overwrite vCPU register. \n";
            } 
            else 
            {
                std::cout << "ACTION    | File Handle request disrupted - RSP overwritten." << "\n";
            }
        }

    }
    drakvuf_resume(drakvuf);
    
}

void deception_net_user_get_info(vmi_instance_t vmi, drakvuf_trap_info* info) {
    ApimonReturnHookData* data = (ApimonReturnHookData*)info->trap->data; // Get the data from the trap
    std::vector<uint64_t> temp_args = data->arguments; // Store all the arguments passed by the function
    std::cout << "    *bufptr: 0x" << std::hex << temp_args[3] << "\n"; // Print the address of the 4th arg
    vmi_pid_t curr_pid = data->target->pid;
    addr_t bufptr = temp_args[3]; // Store address of bufptr
    uint64_t pUserInfo_3 = 0; // Store address of User_Info_3 struct
    uint64_t pUsri3_name = 0; // Store address of Usri3_name struct
    
    if (VMI_FAILURE == vmi_read_64_va(vmi, bufptr, curr_pid, &pUserInfo_3)) // Read address at pointer (arg3)
    {
        std::cout << "Error occured 1" << "\n";
    }

    std::cout << "pUserInfo_3: 0x" << std::hex << pUserInfo_3 << "\n";
    if (VMI_FAILURE == vmi_read_64_va(vmi, (addr_t)pUserInfo_3, curr_pid, &pUsri3_name)) // Print address of pUserInfo_3
    {
        std::cout << "Error occured 2" << "\n";
    }
    
    std::cout << "pUsri3_name: 0x" << std::hex << pUsri3_name << "\n"; // Print address of pointer to usri3_name
    if (temp_args[2] == 3)
    {
        std::cout << "Found: USER_INFO_3 struct!" << "\n";
        /*  Replace Tester with Batman
            Batman = 42 00 61 00 74 00 6d 00 61 00 6e 00 */
        uint8_t fake_user[12] = {66, 0, 97, 0, 116, 0, 109, 0, 97, 0, 110, 0};
        for (uint8_t byte : fake_user)
        {
            if (VMI_FAILURE == vmi_write_8_va(vmi, (addr_t)pUsri3_name, curr_pid, &byte))
            {
                std::cout << "Writing to mem failed!" << "\n";
                break;
            }
            pUsri3_name++; // move address 1 byte
        }

        std::cout << "Replaced username with 'Batman' !" << "\n";

    } else if (temp_args[2] == 2) {
        std::cout << "Found: USER_INFO_2 struct!" << "\n";
    } else {
        std::cout << "Unsupported USER_INFO_X struct!" << "\n";
    }
}

void deception_lookup_account_sid_w(vmi_instance_t vmi, drakvuf_trap_info* info) {
    vmi_pid_t curr_pid = info->attached_proc_data.pid; // Get PID of process
    addr_t pSID = info->regs->rdx; // Get address of PSID
    uint8_t fake_SID[16] = {1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0, 0, 0, 0, 0}; // Replace current user SID with system
    /*  REAL System user SID
        01 01 00 00 00 00 00 05 18 00 00 00 00 00 00 00 */

    for (uint8_t byte: fake_SID) // Modify input argument 2
    {
        if (VMI_FAILURE == vmi_write_8_va(vmi, (addr_t)pSID, curr_pid, &byte))
        {
            std::cout << "Writing to mem failed!" << "\n";
            break;
        }
        pSID++; // move address 1 byte
    }
}

void deception_icmp_send_echo_2_ex(drakvuf_t drakvuf, drakvuf_trap_info* info) {
    std::cout << "Pausing guest..." << "\n";
    drakvuf_pause(drakvuf);
    sleep(3); // Remove for performance improvement
    drakvuf_resume(drakvuf);
    std::cout << "Resuming guest..." << "\n";
}

void deception_ssl_decrypt_packet(vmi_instance_t vmi, drakvuf_trap_info* info, drakvuf_t drakvuf) {
std::cout << "Hit SslDecryptPacket function!" << "\n";    
    ApimonReturnHookData* data = (ApimonReturnHookData*)info->trap->data; // Get the data from the trap
    std::vector<uint64_t> temp_args = data->arguments; // Store all the arguments passed by the function
    uint64_t decrypted_data_p = 0;
    vmi_pid_t curr_pid = info->attached_proc_data.pid; // Get PID of process
    
    addr_t pbOutput = temp_args[4]; // Address of 5th arg (A pointer to a buffer to contain the decrypted packet)
    std::cout << "pbOutput: 0x" << std::hex << pbOutput << "\n";

    addr_t cbOutput = (uint32_t)temp_args[5]; // IN GET LOWER PART OF 64 addrm, Address of 6th arg (The length, bytes, of the pbOutput buffer)
    std::cout << "Len of pOutput: " << cbOutput << "\n";

    drakvuf_pause(drakvuf);
    if (VMI_FAILURE == vmi_read_64_va(vmi, pbOutput, curr_pid, &decrypted_data_p)) // Get address of decrypted_data
    {
        std::cout << "Error reading pbOutput!" << "\n";
    }
    std::cout << "decrypted_data: 0x"  << decrypted_data_p << "\n"; // Print actual decrypted_data content    
    
    uint8_t poc_string[10] = {95,95,95,95,95,95,95,95,95,95}; // Replace 10 bytes in the buffer with "__________", only supports small TEXT files
    // TODO
    // Search for a double CRLF pattern which
    // marks the end of the fields section of
    // a message.
    //uint8_t pattern[4] = { 13, 10, 13, 10 };
    addr_t pBuffer_http_body = pbOutput + (cbOutput - 31);
    for (uint8_t byte : poc_string) // Modify decrypted HTTPS buffer
    {
        if (VMI_FAILURE == vmi_write_8_va(vmi, (addr_t)pBuffer_http_body, curr_pid, &byte))
        {
            std::cout << "Writing to mem failed!" << "\n";
            break;
        }
        pBuffer_http_body++; // move address 1 byte
    }
    drakvuf_resume(drakvuf);
}

void deception_find_first_or_next_file_a(vmi_instance_t vmi, drakvuf_trap_info* info, uint8_t* fake_filename) {
    ApimonReturnHookData* data = (ApimonReturnHookData*)info->trap->data; // Get the data from the trap
    std::vector<uint64_t> temp_args = data->arguments; // Store all the arguments passed by the function
    vmi_pid_t curr_pid = info->attached_proc_data.pid;  // Get PID of process
    uint64_t Win32_Find_Data = 0; // Declare address store for Win32_Find_Data struct
    uint64_t cFileName = 0; // Declare address store for cFileName

    addr_t lpFindFileData = temp_args[1]; // Address of the 2nd arg
    std::cout << "lpFindFileData: 0x" << std::hex << temp_args[1] << "\n";

    if (VMI_FAILURE == vmi_read_64_va(vmi, lpFindFileData, curr_pid, &Win32_Find_Data)) // Read address at pointer (arg2)
    {
        std::cout << "Failed to read memory from VMI\n";
        return;
    }
    std::cout << "WIN32_FIND_DATAA: 0x" << std::hex << Win32_Find_Data << "\n"; // Print address of Win32_Find_Data

    if (VMI_FAILURE == vmi_read_64_va(vmi, (addr_t)(Win32_Find_Data + 44), curr_pid, &cFileName)) // Read address at the offset for the 9th arg in Win32_Find_Data (44 = DWORD*5 + FILETIME*3)
    {
        std::cout << "Error occured 1" << "\n";
    }
    std::cout << "cFileName: 0x" << std::hex << cFileName << "\n"; // Print address of cFileName

    // Need to loop through the array to make work
    for (uint64_t i = 0; i < sizeof(*fake_filename); i++)
    {
        if (VMI_FAILURE == vmi_write_8_va(vmi, (addr_t)cFileName, curr_pid, (fake_filename + i))) {
            std::cout << "Writing to mem failed!" << "\n";
            break;
        }
        cFileName++; // move address 1 byte
    }
}

void deception_bcrypt_decrypt(vmi_instance_t vmi, drakvuf_trap_info* info, drakvuf_t drakvuf) {
    ApimonReturnHookData* data = (ApimonReturnHookData*)info->trap->data; // Get the data from the trap
    std::vector<uint64_t> temp_args = data->arguments;
    if(temp_args[2] != 432) {
        std::cout << "bcrypt.dll: Not Mimikatz\n";
        return;
    }

    std::cout << "Base Addr: " << info->proc_data.base_addr << "\n";
    std::cout << "Name: " << info->attached_proc_data.name << "\n";
    std::cout << "RCX: " << std::hex << temp_args[0] << "\n";
    std::cout << "RDX: " << std::hex << temp_args[1] << "\n";
    std::cout << "R8:  " << std::hex << temp_args[2] << "\n";

    uint64_t process_data[65];
    if(VMI_SUCCESS == vmi_read_va(vmi, info->attached_proc_data.base_addr, info->attached_proc_data.pid, 8, &process_data, NULL)) {
        for(int i = 65; i >= 0; i--) {
            std::cout << process_data[i];
        }
        std::cout << "\n";
    }
    
    // uint64_t rcx[450];
    // addr_t list_head = 0;
    // if(VMI_FAILURE == vmi_read_addr_ksym(vmi, "_KIWI_MSV1_0_PRIMARY_CREDENTIALS", &list_head)) {
    //     printf("Failed to find _KIWI_MSV1_0_PRIMARY_CREDENTIALS\n");
    //     return;
    // }
    // std::cout << "ADDR _KIWI_MSV1_0_PRIMARY_CREDENTIALS: " << list_head << "\n";
    
    // if(vmi_read_va(vmi, temp_args[0], info->proc_data.pid, 448, &rcx, NULL) == VMI_FAILURE) {
    //     std::cout << "Failed to read RCX.\n";
    //     return;
    // }

    // for(int i = 449; i >= 0; i--) {
    //     std::cout << rcx[i];
    // }
    // std::cout << "\n";

    // This is a really crude method, it just overwrites the data
    // uint64_t buf[432] = {0};
    // if(vmi_write_va(vmi, temp_args[1], info->proc_data.pid, 432, &buf, NULL) == VMI_FAILURE) {
    //     std::cout << "Failed to overwrite LSASS struct.\n";
    //     return;
    // }
    // std::cout << "Successfully overwrote LASS struct.\n";
}

void deception_create_tool_help_32_snapshot(vmi_instance_t vmi, drakvuf_trap_info* info, drakvuf_t drakvuf) {
    return;
}

void deception_process_32_first_w(vmi_instance_t vmi, drakvuf_trap_info* info, drakvuf_t drakvuf) {
    if(info->regs->rax == 0) { // If RAX is 0, then the function failed
        std::cout << "RAX is 0, reached end of Linked List.\n";
        return;
    }

    struct PROCESSENTRY32W {
        uint32_t dwSize; // 4 bytes
        uint32_t cntUsage; // 4 bytes
        uint32_t th32ProcessID; // 4 bytes
        uintptr_t th32DefaultHeapID; // 8 bytes
        uint32_t th32ModuleID; // 4 bytes
        uint32_t cntThreads; // 4 bytes
        uint32_t th32ParentProcessID; // 4 bytes
        int32_t pcPriClassBase; // 4 bytes
        uint32_t dwFlags; // 4 bytes
        wchar_t szExeFile[MAX_PATH]; // 2 bytes * 260
    } pe32;
    
    ApimonReturnHookData* data = (ApimonReturnHookData*)info->trap->data; // Get the data from the trap
    std::vector<uint64_t> args = data->arguments;
    
    if(vmi_read_va(vmi, args[1], info->proc_data.pid, 572, &pe32, NULL) == VMI_FAILURE) {
        std::cout << "Failed to read PROCESSENTRY32W.\n";
    } else {
        std::cout << "dwSize: " << pe32.dwSize << "\n";
        std::cout << "cntUsage: " << pe32.cntUsage << "\n";
        std::cout << "th32ProcessID: " << pe32.th32ProcessID << "\n";
        std::cout << "th32DefaultHeapID: " << pe32.th32DefaultHeapID << "\n";
        std::cout << "th32ModuleID: " << pe32.th32ModuleID << "\n";
        std::cout << "cntThreads: " << pe32.cntThreads << "\n";
        std::cout << "th32ParentProcessID: " << pe32.th32ParentProcessID << "\n";
        std::cout << "pcPriClassBase: " << pe32.pcPriClassBase << "\n";
        std::cout << "dwFlags: " << pe32.dwFlags << "\n";

        std::wcout << "szExeFile: " << pe32.szExeFile << "\n";
        std::cout << "-----------\n";
    }
}