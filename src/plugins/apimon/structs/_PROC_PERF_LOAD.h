#pragma once

#include "WinTypes.h"


//0x2 bytes (sizeof)
struct _PROC_PERF_LOAD
{
    UCHAR BusyPercentage;                                                   //0x0
    UCHAR FrequencyPercentage;                                              //0x1
}; 