#include <libvmi/libvmi.h>
#include "../apimon.h"
#include <iostream>

#define MAX_PATH 260

void deception_process_32_first_w(vmi_instance_t vmi, drakvuf_trap_info* info, drakvuf_t drakvuf) {
    return;
    if(info->regs->rax == 0) { // If RAX is 0, then the function failed
        std::cout << "RAX is 0, reached end of Linked List.\n";
        return;
    }

    ApimonReturnHookData* data = (ApimonReturnHookData*)info->trap->data; // Get the data from the trap
    std::vector<uint64_t> args = data->arguments;
    struct PROCESSENTRY32W {
        uint32_t dwSize; // 4 bytes
        uint32_t cntUsage; // 4 bytes
        uint32_t th32ProcessID; // 4 bytes
        uintptr_t th32DefaultHeapID; // 8 bytes
        uint32_t th32ModuleID; // 4 bytes
        uint32_t cntThreads; // 4 bytes
        uint32_t th32ParentProcessID; // 4 bytes
        int32_t pcPriClassBase; // 4 bytes
        uint32_t dwFlags; // 4 bytes
        uint16_t szExeFile[MAX_PATH]; // 2 bytes * 260
    } pe32;


    if(vmi_read_va(vmi, args[1], info->proc_data.pid, sizeof(pe32), &pe32, NULL) == VMI_FAILURE) {
        std::cout << "Failed to read PROCESSENTRY32W.\n";
        return;
    } 
    
    std::cout << "dwSize: " << std::dec << pe32.dwSize << "\n";
    std::cout << "cntUsage: " << std::dec << pe32.cntUsage << "\n";
    std::cout << "th32ProcessID: " << std::dec << pe32.th32ProcessID << "\n";
    std::cout << "th32DefaultHeapID: " << std::dec << pe32.th32DefaultHeapID << "\n";
    std::cout << "th32ModuleID: " << std::dec << pe32.th32ModuleID << "\n";
    std::cout << "cntThreads: " << std::dec << pe32.cntThreads << "\n";
    std::cout << "th32ParentProcessID: " << std::dec << pe32.th32ParentProcessID << "\n";
    std::cout << "pcPriClassBase: " << std::dec << pe32.pcPriClassBase << "\n";
    std::cout << "dwFlags: " << std::dec << pe32.dwFlags << "\n";

    std::ostringstream convert_exefile;
    for (ulong i = 0; i < sizeof(pe32.szExeFile); i++) {
        if(isprint((int)pe32.szExeFile[i]) > 0) {
            convert_exefile << (char)pe32.szExeFile[i];
        } else {
            break;
        }
    }

    std::string convert_exefile_str = convert_exefile.str();
    std::cout << "szExeFile: "<< convert_exefile_str << "\n";
    
    if(
        strcmp(convert_exefile_str.c_str(), "conhost.exe") != 0 &&
        strcmp(convert_exefile_str.c_str(), "ProcessList.exe") != 0
    ) {
        std::cout << "-----------\n";
        return;
    }

    PROCESSENTRY32W pe32mod = {
        .dwSize = pe32.dwSize,
        .cntUsage = pe32.cntUsage,
        .th32ProcessID = pe32.th32ProcessID,
        .th32DefaultHeapID = pe32.th32DefaultHeapID,
        .th32ModuleID = pe32.th32ModuleID,
        .cntThreads = pe32.cntThreads,
        .th32ParentProcessID = pe32.th32ParentProcessID,
        .pcPriClassBase = pe32.pcPriClassBase,
        .dwFlags = pe32.dwFlags,
        .szExeFile = {0x46, 0x61, 0x6b, 0x65, 0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x2e, 0x65, 0x78, 0x65}
    };

    if(vmi_write_va(vmi, args[1], info->proc_data.pid, sizeof(pe32mod), &pe32mod, NULL) == VMI_FAILURE) {
        std::cout << "Failed to write PROCESSENTRY32W.\n";
    } else {
        std::cout << "Successfully wrote PROCESSENTRY32W.\n";
    }
    std::cout << "-----------\n";
    
}