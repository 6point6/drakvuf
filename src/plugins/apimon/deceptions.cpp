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
#include <iostream>

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
 
        //std::u16string u16_file_to_protect = convert_string_to_u16string(file_to_protect);    // Migrate from this line to before the equality check out of the loop for performance. 
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

void deception_bcrypt_decrypt(vmi_instance_t vmi, drakvuf_t drakvuf, drakvuf_trap_info* info, deception_plugin_config* config) {
    ApimonReturnHookData* data = (ApimonReturnHookData*)info->trap->data; 
    std::vector<uint64_t> temp_args = data->arguments;
    vmi_pid_t curr_pid = data->target->pid;

    if(temp_args[2] == 0x1B0) {                         // Mimikatz extractions are based on a fixed length. 0x1B0 for MSV, 0x40 for DPAPI. 
        std::cout << "Mimikatz Identified (MSV1_0)!" << "\n";

        addr_t ntlm_address = temp_args[1]+0x4a;
        addr_t user_address = temp_args[1]+0x1a0;
        addr_t dom_address  = temp_args[1]+0x180;
        addr_t sha1_address = temp_args[1]+0x6a;

        uint16_t extracted_ntlm[8];
        if(VMI_FAILURE == vmi_read_va(vmi, ntlm_address, curr_pid, 16, &extracted_ntlm, nullptr)){
            std::cout << "Unable to read NTLM hash." << "\n";
        }

        //========================================================================
        // Below is just for printing and can be commented out when not debugging   
        std::ostringstream convert;
        for (ulong i = 0; i < sizeof(extracted_ntlm)/2; i++) {
            convert << std::hex << (int)swap_uint16(extracted_ntlm[i]);
        }

        std::string extracted_ntlm_string = convert.str();
        std::cout << "Decrypted NTLM: " << extracted_ntlm_string << "\n";
        // std::cout << std::hex << extracted_ntlm << "\n";

        //========================================================================
        // Overwrite the NTLM hash. Some thought needs to go into this to understand what we want to write and to maintain some record of 
        // what we've said before so that we have consistency. Maybe a sensible answer is to lookup the User ID from Redis and pull the 
        // intended response from there?

        std::vector<uint8_t> new_ntlm_hash = {0xde, 0xad, 0xbe, 0xef,0xde, 0xad, 0xbe, 0xef,0xde, 0xad, 0xbe, 0xef,0xde, 0xad, 0xbe, 0xef};
        for (uint8_t byte: new_ntlm_hash)
        {
            if (VMI_FAILURE == vmi_write_8_va(vmi, ntlm_address, curr_pid, &byte))
            {
                std::cout << "Unable to write new NTLM hash." << "\n";
                break;
            }
            ntlm_address++; // move address 1 byte
        }

        //========================================================================
        // Repeat the above process but for usernames.

        uint16_t extracted_user[21]; // SAM account names have a 20 char limit so this handles the length plus a null-terminator.
        if(VMI_FAILURE == vmi_read_va(vmi, user_address,curr_pid,20,&extracted_user, nullptr)){
            std::cout << "Unable to read User." << "\n";
        }

        std::ostringstream convert_user;
        for (ulong i = 0; i < sizeof(extracted_user)/2; i++) {
            if(extracted_user[i] != 0) {
                convert_user << (char)extracted_user[i];
            }
        }

        std::string extracted_user_string = convert_user.str();
        std::cout << "Decrypted User: "<< extracted_user_string << "\n";

        std::vector<uint8_t> new_username = {0x43, 0x00, 0x70, 0x00, 0x74, 0x00, 0x2E, 0x00, 0x20, 0x00, 0x57, 0x00, 0x57, 0x00, 0x00, 0x00};

        for (uint8_t byte: new_username)
        {
            if (VMI_FAILURE == vmi_write_8_va(vmi, user_address, curr_pid, &byte))
            {
                std::cout << "Unable to write new username." << "\n";
                break;
            }
            user_address++; // move address 1 byte
        }
        //========================================================================
        // Repeat the above process but for Domains...
        uint16_t extracted_domain[30]; // SAM account names have a 20 char limit so this handles the length plus a null-terminator.
        if(VMI_FAILURE == vmi_read_va(vmi, dom_address,curr_pid,40,&extracted_domain, nullptr)){
            std::cout << "Unable to read User." << "\n";
        }

        std::ostringstream convert_domain;
        for (ulong i = 0; i < sizeof(extracted_domain)/2; i++) {
            if(extracted_domain[i] != 0) {
                convert_domain << (char)extracted_domain[i];
            }
        }

        std::string extracted_domain_string = convert_domain.str();
        std::cout << "Decrypted Domain: "<< extracted_domain_string << "\n";

        unicode_string_t* domain_ustr = vmi_read_unicode_str_va(vmi, temp_args[1]+0xb0, curr_pid);
        std::string domain = convert_ustr_to_string(domain_ustr); 
        std::cout << "Ustr: " << domain << "\n";


        std::vector<uint8_t> new_domain = {0x44, 0x00, 0x45, 0x00, 0x53, 0x00, 0x4b, 0x00, 0x54, 0x00, 0x4f, 0x00, 0x50, 0x00, 0x2d, 0x00, 
                                            0x56, 0x00, 0x31, 0x00, 0x33, 0x00, 0x54, 0x00, 0x4e, 0x00, 0x34, 0x00, 0x4d, 0x00};

        for (uint8_t byte: new_domain)
        {
            if (VMI_FAILURE == vmi_write_8_va(vmi, dom_address, curr_pid, &byte))
            {
                std::cout << "Unable to write new domain." << "\n";
                break;
            }
            dom_address++; // move address 1 byte
        }
        //========================================================================
        // Repeat the above process but for SHA1...
        uint16_t extracted_sha1[21];
        if(VMI_FAILURE == vmi_read_va(vmi, sha1_address, curr_pid, 20, &extracted_sha1, nullptr)){
            std::cout << "Unable to read NTLM hash." << "\n";
        }

        //========================================================================
        // Below is just for printing and can be commented out when not debugging   
        std::ostringstream convert_sha1;
        for (ulong i = 0; i < sizeof(extracted_sha1)/2; i++) {
            convert_sha1 << std::hex << (int)swap_uint16(extracted_sha1[i]);
        }

        std::string extracted_sha1_string = convert_sha1.str();
        std::cout << "Decrypted SHA1: " << extracted_sha1_string << "\n";
        // std::cout << std::hex << extracted_ntlm << "\n";

        //========================================================================
        // Overwrite the NTLM hash. Some thought needs to go into this to understand what we want to write and to maintain some record of 
        // what we've said before so that we have consistency. Maybe a sensible answer is to lookup the User ID from Redis and pull the 
        // intended response from there?

        std::vector<uint8_t> new_sha1_hash = {0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 
                                                0x00, 0x00, 0x00, 0x00};
        for (uint8_t byte: new_sha1_hash)
        {
            if (VMI_FAILURE == vmi_write_8_va(vmi, sha1_address, curr_pid, &byte))
            {
                std::cout << "Unable to write new SHA1 hash." << "\n";
                break;
            }
            sha1_address++; // move address 1 byte
        }

    } else if(temp_args[2] == 0x40) 
    {
        std::cout << "Mimikatz Identified (DPAPI)!" << "\n";
        addr_t dpapi_address = temp_args[1];
        uint16_t extracted_dpapi[32];
        if(VMI_FAILURE == vmi_read_va(vmi, dpapi_address, curr_pid, 32, &extracted_dpapi, nullptr)){
            std::cout << "Unable to read NTLM hash." << "\n";
        }

        std::ostringstream convert_dpapi;
        for (ulong i = 0; i < sizeof(extracted_dpapi)/2; i++) {
            convert_dpapi << std::hex << (int)swap_uint16(extracted_dpapi[i]);
        }

        std::string extracted_dpapi_string = convert_dpapi.str();
        std::cout << "Decrypted DPAPI Key: " << extracted_dpapi_string << "\n";

        // std::vector<uint8_t> new_dpapi = {0xde, 0xad, 0xbe, 0xef,0xde, 0xad, 0xbe, 0xef,0xde, 0xad, 0xbe, 0xef,0xde, 0xad, 0xbe, 0xef};
        // for (uint8_t byte: new_dpapi)
        // {
        //     if (VMI_FAILURE == vmi_write_8_va(vmi, ntlm_address, curr_pid, &byte))
        //     {
        //         std::cout << "Unable to write new HTLM hash." << "\n";
        //         break;
        //     }
        //     dpapi_address++; // move address 1 byte
        // }
    }
}

void deception_create_tool_help_32_snapshot(vmi_instance_t vmi, drakvuf_trap_info* info, drakvuf_t drakvuf) {
    return;
    std::cout << "RAX: " << std::hex << info->regs->rax << "\n";
    addr_t list_head = 0;
    int LIST_ENTRY_BASE_OFFSET = 0x448;

    struct _LIST_ENTRY {
        struct _LIST_ENTRY *Flink;
        struct _LIST_ENTRY *Blink;
    } LIST_ENTRY, HandleTableList;
    
    // Get the address of the PsActiveProcessHead
    if(VMI_FAILURE == vmi_read_addr_ksym(vmi, "PsActiveProcessHead", &list_head)) {
        printf("Failed to find PsActiveProcessHead\n");
        return;
    }
    std::cout << "PsActiveProcessHead: 0x" << std::hex << list_head << "\n";
    
    // Read the LIST_ENTRY structure
    if(VMI_FAILURE == vmi_read_va(vmi, list_head, 0, sizeof(LIST_ENTRY), &LIST_ENTRY, NULL)) {
        printf("Failed to read LIST_ENTRY\n");
        return;
    }

    addr_t END_LINK = (addr_t)LIST_ENTRY.Blink;
    while((addr_t)LIST_ENTRY.Flink != END_LINK) {
        char ImageFileName[16];
        addr_t _EPROCESS = (addr_t)LIST_ENTRY.Flink - LIST_ENTRY_BASE_OFFSET;
        addr_t ImageFileName_addr = _EPROCESS + 0x5a8;

        if(VMI_FAILURE == vmi_read_va(vmi, ImageFileName_addr, 0, sizeof(ImageFileName), &ImageFileName, NULL)) {
            printf("Failed to read next pointer.\n");
            return;
        }        

        if(std::string(info->attached_proc_data.name).find(std::string(ImageFileName)) != std::string::npos) {
            std::cout << "Found Attached Process: " << ImageFileName << "\n";
            // Get the next structure
            addr_t _HANDLE_TABLE = _EPROCESS + 0x570;
            addr_t HandleTableList_addr = _HANDLE_TABLE + 0x18;
            
            if(VMI_FAILURE == vmi_read_va(vmi, HandleTableList_addr, 0, sizeof(HandleTableList), &HandleTableList, NULL)) {
                printf("Failed to read LIST_ENTRY\n");
                return;
            }

            addr_t HT_END_LINK = (addr_t)HandleTableList.Blink;
            std::cout << "Flink: " << std::hex << HandleTableList.Flink << "\n";
            std::cout << "Blink: " << std::hex << HandleTableList.Blink << "\n";
            while((addr_t)HandleTableList.Flink != HT_END_LINK) {
                uint64_t TableCode;
                if(VMI_FAILURE == vmi_read_va(vmi, _HANDLE_TABLE + 0x8, 0, sizeof(TableCode), &TableCode, NULL)) {
                    printf("ActualEntry Failed to read next pointer.\n");
                }

                std::cout << "TableCode: " << std::hex << TableCode << "\n";
                std::cout << "Flink: " << std::hex << HandleTableList.Flink << "\n";
                std::cout << "Blink: " << std::hex << HandleTableList.Blink << "\n";

                // Get the next structure
                if(VMI_FAILURE == vmi_read_va(vmi, (addr_t)HandleTableList.Flink, 0, sizeof(HandleTableList), &HandleTableList, NULL)) {
                    printf("Failed to read next pointer.\n");
                    return;
                }
            }
        }

        // Get the next structure
        if(VMI_FAILURE == vmi_read_va(vmi, (addr_t)LIST_ENTRY.Flink, 0, sizeof(LIST_ENTRY), &LIST_ENTRY, NULL)) {
            printf("Failed to read next pointer.\n");
            return;
        }
    }
}

void deception_process_32_first_w(vmi_instance_t vmi, drakvuf_trap_info* info, drakvuf_t drakvuf) {
    if(info->regs->rax == 0) { // If RAX is 0, then the function failed
        std::cout << "RAX is 0, reached end of Linked List.\n";
        return;
    }

    ApimonReturnHookData* data = (ApimonReturnHookData*)info->trap->data; // Get the data from the trap
    std::vector<uint64_t> args = data->arguments;
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
        uint16_t szExeFile[MAX_PATH]; // 2 bytes * 260
    } pe32;


    if(vmi_read_va(vmi, args[1], info->proc_data.pid, sizeof(pe32), &pe32, NULL) == VMI_FAILURE) {
        std::cout << "Failed to read PROCESSENTRY32W.\n";
        return;
    } 
    
    std::cout << "dwSize: " << std::dec << pe32.dwSize << "\n";
    std::cout << "cntUsage: " << std::dec << pe32.cntUsage << "\n";
    std::cout << "th32ProcessID: " << std::dec << pe32.th32ProcessID << "\n";
    std::cout << "th32DefaultHeapID: " << std::dec << pe32.th32DefaultHeapID << "\n";
    std::cout << "th32ModuleID: " << std::dec << pe32.th32ModuleID << "\n";
    std::cout << "cntThreads: " << std::dec << pe32.cntThreads << "\n";
    std::cout << "th32ParentProcessID: " << std::dec << pe32.th32ParentProcessID << "\n";
    std::cout << "pcPriClassBase: " << std::dec << pe32.pcPriClassBase << "\n";
    std::cout << "dwFlags: " << std::dec << pe32.dwFlags << "\n";

    std::ostringstream convert_exefile;
    for (ulong i = 0; i < sizeof(pe32.szExeFile); i++) {
        if(isprint((int)pe32.szExeFile[i]) > 0) {
            convert_exefile << (char)pe32.szExeFile[i];
        } else {
            break;
        }
    }

    std::string convert_exefile_str = convert_exefile.str();
    std::cout << "szExeFile: "<< convert_exefile_str << "\n";
    
    if(
        strcmp(convert_exefile_str.c_str(), "conhost.exe") != 0 &&
        strcmp(convert_exefile_str.c_str(), "ProcessList.exe") != 0
    ) {
        std::cout << "-----------\n";
        return;
    }

    PROCESSENTRY32W pe32mod = {
        .dwSize = pe32.dwSize,
        .cntUsage = pe32.cntUsage,
        .th32ProcessID = pe32.th32ProcessID,
        .th32DefaultHeapID = pe32.th32DefaultHeapID,
        .th32ModuleID = pe32.th32ModuleID,
        .cntThreads = pe32.cntThreads,
        .th32ParentProcessID = pe32.th32ParentProcessID,
        .pcPriClassBase = pe32.pcPriClassBase,
        .dwFlags = pe32.dwFlags,
        .szExeFile = {0x46, 0x61, 0x6b, 0x65, 0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x2e, 0x65, 0x78, 0x65}
    };

    if(vmi_write_va(vmi, args[1], info->proc_data.pid, sizeof(pe32mod), &pe32mod, NULL) == VMI_FAILURE) {
        std::cout << "Failed to write PROCESSENTRY32W.\n";
    } else {
        std::cout << "Successfully wrote PROCESSENTRY32W.\n";
    }
    std::cout << "-----------\n";
    
}

void deception_filter_find(vmi_instance_t vmi, drakvuf_trap_info *info, drakvuf_t drakvuf)
{
    ApimonReturnHookData *data = (ApimonReturnHookData *)info->trap->data;
    std::vector<uint64_t> temp_args = data->arguments;
    vmi_pid_t curr_pid = info->attached_proc_data.pid;
    addr_t xBuffLocation;
    size_t xBuffSize;
    const size_t REPLACEMENT_SIZE = 28;

    if (!strcmp(info->trap->name, "FilterFindFirst"))
    {
        xBuffLocation = temp_args[1];
        xBuffSize = temp_args[2];
    }
    else
    {
        xBuffLocation = temp_args[2];
        xBuffSize = temp_args[3];
    }

    unsigned char *aFilterBuff = new unsigned char[xBuffSize];

    // reading and storing buffer
    if (VMI_FAILURE == vmi_read_va(vmi, xBuffLocation, curr_pid, xBuffSize, aFilterBuff, NULL))
    {
        std::cout << "Failed to read memory from VMI (this is next check) "
                  << &aFilterBuff << "\n";
        return;
    }

    unsigned char *aReplacement = new unsigned char[REPLACEMENT_SIZE]{77, 0, 121, 0, 66, 0, 97, 0, 99, 0, 107, 0, 117, 0, 112, 0, 50, 0, 56, 0, 51, 0, 48, 0, 53, 0, 48, 0};

    // adding null terminator
    aReplacement[REPLACEMENT_SIZE] = '\0';

    // converting buffer to string
    // std::string sFindNext(aFilterBuff, aFilterBuff + xBuffSize);

    // looping through buffer and looking for WdFilter
    // std::cout << "filter: ";
    for (size_t i = 0; i < xBuffSize; i++)
    {
        if (aFilterBuff[i] == 'W' && aFilterBuff[i + 2] == 'd')
        {
            for (size_t j = 0; j < REPLACEMENT_SIZE; j++)
            {
                aFilterBuff[i + j] = aReplacement[j];
            }

            // writing altered buffer
            if (VMI_FAILURE == vmi_write_va(vmi, xBuffLocation, curr_pid, xBuffSize, aFilterBuff, NULL))
            {
                std::cout << "Failed to read memory from VMI (this is next check) "
                          << &aFilterBuff << "\n";
                return;
            }
        }
        // std::cout << aFilterBuff[i];
    }
    // std::cout << "\n";

    // outputing the buffer details to the console as string
    // if (!(sFindNext.empty()))
    // {
    //     sFindNext.erase(std::remove_if(sFindNext.begin(), sFindNext.end(), ::isspace), sFindNext.end());
    //     std::cout << "filter: " << sFindNext << "\n";
    //     std::cout << "memory address: " << std::hex << &aFilterBuff << "\n";
    //     std::cout << "Size: " << xBuffSize << "\n";
    // }

    // added to prevent memory leaks
    delete[] aFilterBuff;
}