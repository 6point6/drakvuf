#pragma once

#include "WinTypes.h"


//0x10 bytes (sizeof)
struct _PO_FX_PERF_STATE_CHANGE
{
    ULONG Set;                                                              //0x0
    union
    {
        ULONG StateIndex;                                                   //0x8
        ULONGLONG StateValue;                                               //0x8
    };
}; 