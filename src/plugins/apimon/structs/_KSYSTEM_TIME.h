#pragma once

#include "WinTypes.h"


//0xc bytes (sizeof)
struct _KSYSTEM_TIME
{
    ULONG LowPart;                                                          //0x0
    LONG High1Time;                                                         //0x4
    LONG High2Time;                                                         //0x8
}; 