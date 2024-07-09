#pragma once

#include "WinTypes.h"


//0x54 bytes (sizeof)
struct _IOP_IRP_STACK_PROFILER
{
    ULONG Profile[20];                                                      //0x0
    ULONG TotalIrps;                                                        //0x50
}; 