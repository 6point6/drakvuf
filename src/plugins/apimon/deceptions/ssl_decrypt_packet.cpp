#include <libvmi/libvmi.h>
#include "../apimon.h"
#include <iostream>

void deception_ssl_decrypt_packet(vmi_instance_t vmi, drakvuf_trap_info* info, drakvuf_t drakvuf) {
    std::cout << "Hit SslDecryptPacket function!" << "\n";    
    ApimonReturnHookData* data = (ApimonReturnHookData*)info->trap->data; // Get the data from the trap
    std::vector<uint64_t> temp_args = data->arguments; // Store all the arguments passed by the function
    uint64_t decrypted_data_p = 0;
    vmi_pid_t curr_pid = info->attached_proc_data.pid; // Get PID of process
    
    addr_t pbOutput = temp_args[4]; // Address of 5th arg (A pointer to a buffer to contain the decrypted packet)
    std::cout << "pbOutput: 0x" << std::hex << pbOutput << "\n";

    addr_t cbOutput = (uint32_t)temp_args[5]; // IN GET LOWER PART OF 64 addrm, Address of 6th arg (The length, bytes, of the pbOutput buffer)
    std::cout << "Len of pOutput: " << cbOutput << "\n";

    drakvuf_pause(drakvuf);
    if (VMI_FAILURE == vmi_read_64_va(vmi, pbOutput, curr_pid, &decrypted_data_p)) // Get address of decrypted_data
    {
        std::cout << "Error reading pbOutput!" << "\n";
    }
    std::cout << "decrypted_data: 0x"  << decrypted_data_p << "\n"; // Print actual decrypted_data content    
    
    uint8_t poc_string[10] = {95,95,95,95,95,95,95,95,95,95}; // Replace 10 bytes in the buffer with "__________", only supports small TEXT files
    // TODO
    // Search for a double CRLF pattern which
    // marks the end of the fields section of
    // a message.
    //uint8_t pattern[4] = { 13, 10, 13, 10 };
    addr_t pBuffer_http_body = pbOutput + (cbOutput - 31);
    for (uint8_t byte : poc_string) // Modify decrypted HTTPS buffer
    {
        if (VMI_FAILURE == vmi_write_8_va(vmi, (addr_t)pBuffer_http_body, curr_pid, &byte))
        {
            std::cout << "Writing to mem failed!" << "\n";
            break;
        }
        pBuffer_http_body++; // move address 1 byte
    }
    drakvuf_resume(drakvuf);
}