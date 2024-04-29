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
    if (ustr->contents != 0) 
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