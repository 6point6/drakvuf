#pragma once

#include "WinTypes.h"


//0x10 bytes (sizeof)
struct _ETW_COUNTERS
{
    LONG GuidCount;                                                         //0x0
    LONG PoolUsage[2];                                                      //0x4
    LONG SessionCount;                                                      //0xc
}; 