#pragma once

#include "WinTypes.h"
#include "PEPHANDLE__.h"

//0x10 bytes (sizeof)
struct _PEP_CRASHDUMP_INFORMATION
{
    struct PEPHANDLE__* DeviceHandle;                                       //0x0
    VOID* DeviceContext;                                                    //0x8
}; 