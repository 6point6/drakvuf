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

std::string convertToUTF8(const unicode_string_t* ustr)
void dcpNtCreateFile(vmi_instance_t vmi, drakvuf_trap_info* info);

#endif