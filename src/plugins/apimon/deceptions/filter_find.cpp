#include <libvmi/libvmi.h>
#include "../apimon.h"
#include <iostream>

void deception_filter_find(vmi_instance_t vmi, drakvuf_trap_info *info, drakvuf_t drakvuf) {
    ApimonReturnHookData *data = (ApimonReturnHookData *)info->trap->data;
    std::vector<uint64_t> temp_args = data->arguments;
    vmi_pid_t curr_pid = info->attached_proc_data.pid;
    addr_t xBuffLocation;
    size_t xBuffSize;
    const size_t REPLACEMENT_SIZE = 28;

    if (!strcmp(info->trap->name, "FilterFindFirst"))
    {
        xBuffLocation = temp_args[1];
        xBuffSize = temp_args[2];
    }
    else
    {
        xBuffLocation = temp_args[2];
        xBuffSize = temp_args[3];
    }

    unsigned char *aFilterBuff = new unsigned char[xBuffSize];

    // reading and storing buffer
    if (VMI_FAILURE == vmi_read_va(vmi, xBuffLocation, curr_pid, xBuffSize, aFilterBuff, NULL))
    {
        std::cout << "Failed to read memory from VMI (this is next check) "
                  << &aFilterBuff << "\n";
        return;
    }

    unsigned char *aReplacement = new unsigned char[REPLACEMENT_SIZE]{77, 0, 121, 0, 66, 0, 97, 0, 99, 0, 107, 0, 117, 0, 112, 0, 50, 0, 56, 0, 51, 0, 48, 0, 53, 0, 48, 0};

    // adding null terminator
    aReplacement[REPLACEMENT_SIZE] = '\0';

    // converting buffer to string
    // std::string sFindNext(aFilterBuff, aFilterBuff + xBuffSize);

    // looping through buffer and looking for WdFilter
    // std::cout << "filter: ";
    for (size_t i = 0; i < xBuffSize; i++)
    {
        if (aFilterBuff[i] == 'W' && aFilterBuff[i + 2] == 'd')
        {
            for (size_t j = 0; j < REPLACEMENT_SIZE; j++)
            {
                aFilterBuff[i + j] = aReplacement[j];
            }

            // writing altered buffer
            if (VMI_FAILURE == vmi_write_va(vmi, xBuffLocation, curr_pid, xBuffSize, aFilterBuff, NULL))
            {
                std::cout << "Failed to read memory from VMI (this is next check) "
                          << &aFilterBuff << "\n";
                return;
            }
        }
        // std::cout << aFilterBuff[i];
    }
    // std::cout << "\n";

    // outputing the buffer details to the console as string
    // if (!(sFindNext.empty()))
    // {
    //     sFindNext.erase(std::remove_if(sFindNext.begin(), sFindNext.end(), ::isspace), sFindNext.end());
    //     std::cout << "filter: " << sFindNext << "\n";
    //     std::cout << "memory address: " << std::hex << &aFilterBuff << "\n";
    //     std::cout << "Size: " << xBuffSize << "\n";
    // }

    // added to prevent memory leaks
    delete[] aFilterBuff;
}