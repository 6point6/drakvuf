/*****************************************************************************
 * Splits out the new deception code from the rest of apimon with the        *
 * intention of making this a little easier to read and maintain - if we can *
 * leave apimon alone then that's one fewer thing to break! There's also the *
 * advantage that we may not only be reliant on apimon going forward so this *
 * should make any future refactor easier too.                               * 
 *****************************************************************************/

#ifndef DECEPTIONS_H
#define DECEPTIONS_H

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

std::string convert_to_utf_8(const unicode_string_t* ustr);

void deception_nt_create_file(vmi_instance_t vmi, drakvuf_trap_info* info);
void deception_net_user_get_info(vmi_instance_t vmi, drakvuf_trap_info* info);
void deception_lookup_account_sid_w(vmi_instance_t vmi, drakvuf_trap_info* info);
void deception_icmp_send_echo_2_ex(drakvuf_t drakvuf, drakvuf_trap_info* info);
void deception_ssl_decrypt_packet(vmi_instance_t vmi, drakvuf_trap_info* info, drakvuf_t drakvuf);
void deception_find_first_or_next_file_a(vmi_instance_t vmi, drakvuf_trap_info* info, uint8_t* fake_filename);

#endif