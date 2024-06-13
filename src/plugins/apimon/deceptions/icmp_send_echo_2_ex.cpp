#include <libvmi/libvmi.h>
#include "../apimon.h"
#include <iostream>

void deception_icmp_send_echo_2_ex(drakvuf_t drakvuf, drakvuf_trap_info* info) {
    std::cout << "Pausing guest..." << "\n";
    drakvuf_pause(drakvuf);
    sleep(3); // Remove for performance improvement
    drakvuf_resume(drakvuf);
    std::cout << "Resuming guest..." << "\n";
}