#include <iostream>
#include <stdexcept>
#include <inttypes.h>
#include <assert.h>
#include <vector>
#include <string>
#include <cstring>
#include <codecvt>
#include <locale>
#include "plugins/output_format.h"
#include "apimon.h" 
#include <bitset>
#include "deception_utils.h"
#include "deceptions.h"
#include <ctime>
#include <sw/redis++/redis++.h>
#include <iconv.h>
#include "intelgathering.h"
#include "deception_types.h"


/// @brief 
/// @param access_mask 
/// @param emvf 
/// @return 
bool has_any_flag(uint32_t access_mask, enum_mask_value_file emvf)
{
    return (access_mask & (int)emvf) != 0;
}


/// @brief Converts a provided UNICODE_STRING to a UTF-16 formatted std::string. 
/// @param ustr UNICODE_STRING to convert 
/// @return Converted string
std::string convert_ustr_to_string(const unicode_string_t* ustr) {
    if (ustr != 0) 
    {
        if (strcmp(ustr->encoding, "UTF-16") == 0) {
            return std::string(reinterpret_cast<const char*>(ustr->contents), ustr->length);
        } else {
            std::cerr << "Unsupported encoding: " << ustr->encoding << "\n";
            return std::string();
        }
        return std::string();   
    }
    return std::string();
}

/// @brief Converts a std::string to a UTF-16 string. 
/// @param u8str String to convert
/// @return Converted string
std::u16string convert_string_to_u16string(std::string u8str) {
    std::wstring_convert<std::codecvt_utf8_utf16<char16_t>,char16_t> convert;
    std::u16string new_u16str = convert.from_bytes(u8str);
    return new_u16str;
}


std::string convertToUtf8(const std::string& input) {
    // Create a UTF-8 converter facet
    std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;

    // Convert the input string to wide string (assuming it is in ISO-8859-1)
    std::wstring wideString(input.begin(), input.end());

    // Convert wide string to UTF-8
    std::string utf8String = converter.to_bytes(wideString);

    return utf8String;
}

bool vector_contains(const std::vector<int>& v, int& t)
{
    bool found = (std::find(v.begin(), v.end(), t) != v.end());
    return found;
}

uint16_t swap_uint16( uint16_t val ) 
{
    return (val << 8) | (val >> 8 );
}


void get_config_from_redis(deception_plugin_config* config) 
{
    time_t time_now = std::time(nullptr); 
    try 
    {
        //std::cout << "Connecting to Redis to update config... ";
        auto redis = sw::redis::Redis("tcp://127.0.0.1:6379");
        //std::cout << "Connected." << "\n";
        //std::cout << "Downloading config... ";

    config->ntcreatefile.enabled =               (bool)std::stoi(redis.get("ntcreatefile_enabled").value_or("0"));              
    config->ntcreatefile.target_string =         (redis.get("ntcreatefile_targetstring")).value_or("\\??\\\\.\\PhysicalDrive0");
    config->netusergetinfo.enabled =             (bool)std::stoi(redis.get("ntcreatefile_enabled").value_or("0"));
    config->lookupaccountsid.enabled =           (bool)std::stoi(redis.get("lookupaccountsid_enabled").value_or("0"));
    config->icmpsendecho2ex.enabled =            (bool)std::stoi(redis.get("icmpsendecho2ex_enabled").value_or("0"));
    config->ssldecryptpacket.enabled =           (bool)std::stoi(redis.get("ssldecryptpacket_enabled").value_or("0"));
    config->findfirstornextfile.enabled =        (bool)std::stoi(redis.get("findfirstornextfile_enabled").value_or("0"));
    config->bcryptdecrypt.enabled =              (bool)std::stoi(redis.get("bcryptdecrypt_enabled").value_or("0"));
    config->createtoolhelp32snapshot.enabled =   (bool)std::stoi(redis.get("createtoolhelp32snapshot_enabled").value_or("0"));
    config->process32firstw.enabled =            (bool)std::stoi(redis.get("process32firstw_enabled").value_or("0"));
    config->filterfind.enabled =                 (bool)std::stoi(redis.get("filterfind_enabled").value_or("0"));
    config->openprocess.enabled =                (bool)std::stoi(redis.get("openprocess_enabled").value_or("0"));
    config->readprocessmemory.enabled =          (bool)std::stoi(redis.get("readprocessmemory_enabled").value_or("0"));
    config->getipnettable.enabled =              (bool)std::stoi(redis.get("getipnettable_enabled").value_or("0"));

    //std::cout << "Done." << "\n";
    
    } catch (const sw::redis::Error &e) 
    {
        //std::cout << e.what() << "\n";
        std::cout << "{";
            std::cout << "\"timestamp\": "      << std::dec << time_now             << ", "; 
            std::cout << "\"type\": "           << "\"config_update\""              << ", ";
            std::cout << "\"action\": "         << "\"FAILURE\""                  << ", ";
            std::cout << "\"message\": "          << "\"" << e.what() << "\""        ;
        std::cout << "}" << "\n";
    }
}


std::vector<uint8_t> string_to_array(std::string str, bool wide){
    std::vector<uint8_t> arr;
    
    if(wide == true){
        for(char c : str) {
            arr.push_back(c);
            arr.push_back(0);
        }
    } 
    else {
        for(char c : str) {
            arr.push_back(c);
            }
    }

    return arr;
}

void printStringAsHex(const std::string& input) {
    std::cout << std::hex << std::setfill('0');
    for (unsigned char c : input) {
        std::cout << std::setw(2) << static_cast<int>(c) << " ";
    }
    std::cout << std::dec << std::endl; // Reset to decimal
}



status_t vmi_overwrite_unicode_str_va(vmi_instance_t vmi, addr_t vaddr, vmi_pid_t pid, std::string str) {

    uint16_t maxsize;
    if (VMI_FAILURE == vmi_read_16_va(vmi, vaddr+0x2, pid, &maxsize)) {
        std::cout << "Unable to read existing unicode string. " << "\n";
        return VMI_FAILURE;
    }

    std::vector<uint8_t> content_buffer = string_to_array(str, true);
    
    uint16_t size = content_buffer.size();
    if (size > maxsize) {
        std::cout << "New string too large, unable to overwrite." << "\n";
        std::cout << "New String [" << str << "] has length " << std::dec << size << ", maximum allowed is " << maxsize << ". \n";
        return VMI_FAILURE;
    }
    
    addr_t pointer;
    if (VMI_FAILURE == vmi_read_addr_va(vmi, vaddr+0x8, pid, &pointer)) {
        return VMI_FAILURE;
    }

    if (VMI_FAILURE == vmi_write_16_va(vmi, vaddr, pid, &size)) {
        std::cout << "Unable to write new size." << "\n";
        return VMI_FAILURE;
    }

    for (uint8_t byte: content_buffer){
        if (VMI_FAILURE == vmi_write_8_va(vmi, pointer, pid, &byte)){
            std::cout << "Unable to write new value." << "\n";
            return VMI_FAILURE;
        }
        pointer++;
    }

    return VMI_SUCCESS;
}

void deception_overwrite_logonsessionlist(vmi_instance_t vmi, system_info sysinfo, std::vector<simple_user>* user_list,
                                                std::vector<simple_user>* new_user_list) {

    status_t success;
    for (simple_user user: *new_user_list) {
        if(user.changed == true) {
            std::cout << "Overwriting LogonSessionList entry at position 0x" << std::hex << user.pstruct_addr << "\n";
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
            
            for (simple_user old_user: *user_list) {
                if (old_user.pstruct_addr == user.pstruct_addr) {
                    old_user.changed = true;
                }
            }
        }
    } 
}


void log_message(const char* level, const char* type, const char* event, const char* action, const char* message) {
    
    time_t time_now = std::time(nullptr);
    std::cout << "{";
        std::cout << "\"timestamp\": "      << std::dec << time_now                 << ", ";
        std::cout << "\"level\": "          << "\"" << level << "\""                << ", ";
        std::cout << "\"type\": "           << "\"" << type << "\""                 << ", ";
        std::cout << "\"event\": "          << "\"" << event << "\""                << ", ";
        std::cout << "\"action\": "         << "\"" << action << "\""               << ", ";
        std::cout << "\"message\": "        << "\"" << message << "\""                 ;
    std::cout << "}" << "\n"; 
}