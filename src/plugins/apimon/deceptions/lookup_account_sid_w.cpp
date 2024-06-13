#include <libvmi/libvmi.h>
#include "../apimon.h"
#include <iostream>

void deception_lookup_account_sid_w(vmi_instance_t vmi, drakvuf_trap_info* info) {
    vmi_pid_t curr_pid = info->attached_proc_data.pid; // Get PID of process
    addr_t pSID = info->regs->rdx; // Get address of PSID
    uint8_t fake_SID[16] = {1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0, 0, 0, 0, 0}; // Replace current user SID with system
    /*  REAL System user SID
        01 01 00 00 00 00 00 05 18 00 00 00 00 00 00 00 */

    for (uint8_t byte: fake_SID) // Modify input argument 2
    {
        if (VMI_FAILURE == vmi_write_8_va(vmi, (addr_t)pSID, curr_pid, &byte))
        {
            std::cout << "Writing to mem failed!" << "\n";
            break;
        }
        pSID++; // move address 1 byte
    }
}