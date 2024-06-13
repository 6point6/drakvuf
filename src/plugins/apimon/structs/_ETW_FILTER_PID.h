#pragma once

#include "WinTypes.h"


//0x24 bytes (sizeof)
struct _ETW_FILTER_PID
{
    ULONG Count;                                                            //0x0
    ULONG Pids[8];                                                          //0x4
}; 