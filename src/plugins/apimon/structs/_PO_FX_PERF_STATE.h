#pragma once

#include "WinTypes.h"


//0x10 bytes (sizeof)
struct _PO_FX_PERF_STATE
{
    ULONGLONG Value;                                                        //0x0
    VOID* Context;                                                          //0x8
}; 