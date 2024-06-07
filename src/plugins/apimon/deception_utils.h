#ifndef DECEPTIONUTILS_H
#define DECEPTIONUTILS_H

#include "apimon.h"
#include <libvmi/libvmi.h>
#include "deception_types.h"



bool has_any_flag(uint32_t access_mask, enum_mask_value_file emvf);

std::string convert_ustr_to_string(const unicode_string_t* ustr);
std::u16string convert_string_to_u16string(std::string u8str);
bool vector_contains(const std::vector<int>& v, int& t);
uint16_t swap_uint16( uint16_t val);
void get_config_from_redis(deception_plugin_config* config);
std::vector<uint8_t> string_to_array(std::string str, bool wide = false);
status_t vmi_overwrite_unicode_str_va(vmi_instance_t vmi, addr_t vaddr, vmi_pid_t pid, std::string str);

#endif