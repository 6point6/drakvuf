#include <libvmi/libvmi.h>
#include "../apimon.h"
#include <iostream>
#include "../deception_utils.h"


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

        //std::vector<uint8_t> new_username = {0x43, 0x00, 0x70, 0x00, 0x74, 0x00, 0x2E, 0x00, 0x20, 0x00, 0x57, 0x00, 0x57, 0x00, 0x00, 0x00};
        std::string newu = "Batman";
        std::vector<uint8_t> new_username = string_to_array(newu, true);

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