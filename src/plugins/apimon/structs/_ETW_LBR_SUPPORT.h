#pragma once

#include "WinTypes.h"


//0x14 bytes (sizeof)
struct _ETW_LBR_SUPPORT
{
    ULONG LbrHandle;                                                        //0x0
    ULONG LbrOptions;                                                       //0x4
    volatile ULONG HookIdCount;                                             //0x8
    USHORT HookId[4];                                                       //0xc
}; 