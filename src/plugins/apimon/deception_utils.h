#ifndef DECEPTIONUTILS_H
#define DECEPTIONUTILS_H

#include <iostream>
#include <assert.h>
#include <vector>
#include <map>
#include <memory>
#include <unordered_map>
#include <optional>
#include <glib.h>
#include <libusermode/userhook.hpp>
#include "plugins/plugins_ex.h"
#include "apimon.h"
#include <libvmi/libvmi.h>

enum class enum_mask_value_file
{
    FILE_WRITE_ATTRIBUTES = 1 << 0, // 1
    FILE_READ_ATTRIBUTES = 1 << 1, // 2
    FILE_EXECUTE = 1 << 2, // 4
    FILE_WRITE_EA = 1 << 3, // 8
    FILE_READ_EA = 1 << 4, // 16
    FILE_APPEND_DATA = 1 << 5, // 32
    FILE_WRITE_DATA = 1 << 6, // 64
    FILE_READ_DATA = 1 << 7,  // 128
    UNUSED_8 = 1 << 8,
    UNUSED_9 = 1 << 9,
    UNUSED_10 = 1 << 10,
    UNUSED_11 = 1 << 11,
    UNUSED_12 = 1 << 12,
    UNUSED_13 = 1 << 13,
    UNUSED_14 = 1 << 14,
    UNUSED_15 = 1 << 15,
    DELETE = 1 << 16,
    READ_CONTROL = 1 << 17,
    WRITE_DAC = 1 << 18, 
    WRITE_OWNER = 1 << 19,
    SYNCHRONIZE = 1 << 20,
    UNUSED_21 = 1 << 21,
    UNUSED_22 = 1 << 22,
    UNUSED_23 = 1 << 23,
    ACCESS_SYSTEM_SECURITY = 1 << 24,
    MAXIMUM_ALLOWED = 1 << 25,
    UNUSED_26 = 1 << 26,
    UNUSED_27 = 1 << 27,
    GENERIC_ALL = 1 << 28,
    GENERIC_EXECUTE = 1 << 29,
    GENERIC_WRITE = 1 << 30,
    GENERIC_READ = 1 << 31
};

bool has_any_flag(uint32_t access_mask, enum_mask_value_file emvf);

std::string convert_ustr_to_string(const unicode_string_t* ustr);
std::u16string convert_string_to_u16string(std::string u8str);

#endif