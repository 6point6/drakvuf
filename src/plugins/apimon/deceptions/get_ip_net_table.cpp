#include <libvmi/libvmi.h>
#include "../apimon.h"
#include <iostream>

void deception_get_ip_net_table(vmi_instance_t vmi, drakvuf_trap_info *info, drakvuf_t drakvuf) {
    std::cout << "HIT IP NET TABLE" << "\n";
}