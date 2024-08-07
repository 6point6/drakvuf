#pragma once

#include "WinTypes.h"


//0xc bytes (sizeof)
struct _IMAGE_RUNTIME_FUNCTION_ENTRY
{
    ULONG BeginAddress;                                                     //0x0
    ULONG EndAddress;                                                       //0x4
    union
    {
        ULONG UnwindInfoAddress;                                            //0x8
        ULONG UnwindData;                                                   //0x8
    };
}; 