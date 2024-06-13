#pragma once

#include "WinTypes.h"


//0x8 bytes (sizeof)
struct _LUID
{
    ULONG LowPart;                                                          //0x0
    LONG HighPart;                                                          //0x4
}; 