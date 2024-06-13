#pragma once

#include "WinTypes.h"
#include "_AGGREGATED_PAYLOAD_FILTER.h"

//0x58 bytes (sizeof)
struct _ETW_PAYLOAD_FILTER
{
    LONG RefCount;                                                          //0x0
    struct _AGGREGATED_PAYLOAD_FILTER PayloadFilter;                        //0x8
}; 