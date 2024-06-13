#pragma once

#include "WinTypes.h"
#include "_LARGE_INTEGER.h"

//0x10 bytes (sizeof)
struct _ETW_REF_CLOCK
{
    union _LARGE_INTEGER StartTime;                                         //0x0
    union _LARGE_INTEGER StartPerfClock;                                    //0x8
}; 