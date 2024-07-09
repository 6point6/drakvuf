#include <libvmi/libvmi.h>
#include "../apimon.h"
#include <iostream>

void deception_create_tool_help_32_snapshot(vmi_instance_t vmi, drakvuf_trap_info* info, drakvuf_t drakvuf) {
    std::cout << "RAX: " << std::hex << info->regs->rax << "\n";
    addr_t list_head = 0;
    // int LIST_ENTRY_BASE_OFFSET = 0x448;

    struct _LIST_ENTRY {
        struct _LIST_ENTRY *Flink;
        struct _LIST_ENTRY *Blink;
    } LIST_ENTRY;

    // _EPROCESS eprocess;
    
    // Get the address of the PsActiveProcessHead
    if(VMI_FAILURE == vmi_read_addr_ksym(vmi, "PsActiveProcessHead", &list_head)) {
        printf("Failed to find PsActiveProcessHead\n");
        return;
    }
    std::cout << "PsActiveProcessHead: 0x" << std::hex << list_head << "\n";
    // std::cout << offsetof(_EPROCESS, ActiveProcessLinks);
    

    if(VMI_FAILURE == vmi_read_va(vmi, list_head, 0, sizeof(LIST_ENTRY), &LIST_ENTRY, NULL)) {
        printf("Failed to read LIST_ENTRY\n");
        return;
    }

    // // Read the LIST_ENTRY structure
    // if(VMI_FAILURE == vmi_read_va(vmi, list_head - offsetof(_EPROCESS, ActiveProcessLinks), info->proc_data.pid, sizeof(_EPROCESS), &eprocess, NULL)) {
    //     printf("Failed to read _EPROCESS\n");
    //     return;
    // }

    std::cout << "Flink: 0x" << std::hex << LIST_ENTRY.Flink << "\n";
    // std::cout << "_EPROCESS Flink: 0x" << std::hex << eprocess.ActiveProcessLinks.Flink << "\n";
}


/*
if(VMI_FAILURE == vmi_read_va(vmi, list_head, 0, sizeof(LIST_ENTRY), &LIST_ENTRY, NULL)) {
        printf("Failed to read LIST_ENTRY\n");
        return;
    }

    addr_t END_LINK = (addr_t)LIST_ENTRY.Blink;
    while((addr_t)LIST_ENTRY.Flink != END_LINK) {
        char ImageFileName[16];
        addr_t _EPROCESS = (addr_t)LIST_ENTRY.Flink - LIST_ENTRY_BASE_OFFSET;
        addr_t ImageFileName_addr = _EPROCESS + 0x5a8;

        if(VMI_FAILURE == vmi_read_va(vmi, ImageFileName_addr, 0, sizeof(ImageFileName), &ImageFileName, NULL)) {
            printf("Failed to read next pointer.\n");
            return;
        }        

        if(std::string(info->attached_proc_data.name).find(std::string(ImageFileName)) != std::string::npos) {
            std::cout << "Found Attached Process: " << ImageFileName << "\n";
            // Get the next structure
            addr_t _HANDLE_TABLE = _EPROCESS + 0x570;
            addr_t HandleTableList_addr = _HANDLE_TABLE + 0x18;
            
            if(VMI_FAILURE == vmi_read_va(vmi, HandleTableList_addr, 0, sizeof(HandleTableList), &HandleTableList, NULL)) {
                printf("Failed to read LIST_ENTRY\n");
                return;
            }

            addr_t HT_END_LINK = (addr_t)HandleTableList.Blink;
            std::cout << "Flink: " << std::hex << HandleTableList.Flink << "\n";
            std::cout << "Blink: " << std::hex << HandleTableList.Blink << "\n";
            while((addr_t)HandleTableList.Flink != HT_END_LINK) {
                uint64_t TableCode;
                if(VMI_FAILURE == vmi_read_va(vmi, _HANDLE_TABLE + 0x8, 0, sizeof(TableCode), &TableCode, NULL)) {
                    printf("ActualEntry Failed to read next pointer.\n");
                }

                std::cout << "TableCode: " << std::hex << TableCode << "\n";
                std::cout << "Flink: " << std::hex << HandleTableList.Flink << "\n";
                std::cout << "Blink: " << std::hex << HandleTableList.Blink << "\n";

                // Get the next structure
                if(VMI_FAILURE == vmi_read_va(vmi, (addr_t)HandleTableList.Flink, 0, sizeof(HandleTableList), &HandleTableList, NULL)) {
                    printf("Failed to read next pointer.\n");
                    return;
                }
            }
        }

        // Get the next structure
        if(VMI_FAILURE == vmi_read_va(vmi, (addr_t)LIST_ENTRY.Flink, 0, sizeof(LIST_ENTRY), &LIST_ENTRY, NULL)) {
            printf("Failed to read next pointer.\n");
            return;
        }
    }
*/