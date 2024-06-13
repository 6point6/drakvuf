#pragma once

#include "WinTypes.h"


//0x20 bytes (sizeof)
struct _MMSUPPORT_AGGREGATION
{
    ULONG PageFaultCount;                                                   //0x0
    ULONGLONG WorkingSetSize;                                               //0x8
    ULONGLONG WorkingSetLeafSize;                                           //0x10
    ULONGLONG PeakWorkingSetSize;                                           //0x18
}; 