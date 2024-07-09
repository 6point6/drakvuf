#pragma once

#include "WinTypes.h"


//0x8 bytes (sizeof)
union _ULARGE_INTEGER
{
    struct
    {
        ULONG LowPart;                                                      //0x0
        ULONG HighPart;                                                     //0x4
    };
    struct
    {
        ULONG LowPart;                                                      //0x0
        ULONG HighPart;                                                     //0x4
    } u;                                                                    //0x0
    ULONGLONG QuadPart;                                                     //0x0
}; 