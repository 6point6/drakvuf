#pragma once

#include "WinTypes.h"
#include "_GUID.h"

//0x10 bytes (sizeof)
struct _DISALLOWED_GUIDS
{
    USHORT Count;                                                           //0x0
    struct _GUID* Guids;                                                    //0x8
}; 