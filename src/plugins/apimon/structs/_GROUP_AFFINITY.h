#pragma once

#include "WinTypes.h"


//0x10 bytes (sizeof)
struct _GROUP_AFFINITY
{
    ULONGLONG Mask;                                                         //0x0
    USHORT Group;                                                           //0x8
    USHORT Reserved[3];                                                     //0xa
}; 