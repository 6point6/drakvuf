#pragma once

#include "WinTypes.h"


//0x10 bytes (sizeof)
struct _KDESCRIPTOR
{
    USHORT Pad[3];                                                          //0x0
    USHORT Limit;                                                           //0x6
    VOID* Base;                                                             //0x8
}; 