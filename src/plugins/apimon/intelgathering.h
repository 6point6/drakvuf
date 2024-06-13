
#ifndef INTELGATHERING_H
#define INTELGATHERING_H

#include "apimon.h"
#include <libvmi/libvmi.h>
#include "deception_types.h"

std::vector<process> list_running_processes(drakvuf_t drakvuf, vmi_instance_t vmi, drakvuf_trap_info* info, system_info* sysinfo, deception_plugin_config* config);
std::vector<simple_user> list_users(drakvuf_t drakvuf, vmi_instance_t vmi, drakvuf_trap_info* info, system_info* sysinfo);

#endif