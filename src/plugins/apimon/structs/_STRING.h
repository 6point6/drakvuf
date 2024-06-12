#pragma once

#include "WinTypes.h"


//0x10 bytes (sizeof)
struct _STRING
{
    USHORT Length;                                                          //0x0
    USHORT MaximumLength;                                                   //0x2
    CHAR* Buffer;                                                           //0x8
}; 