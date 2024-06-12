#pragma once

#include "WinTypes.h"


//0xc bytes (sizeof)
struct _POWER_SEQUENCE
{
    ULONG SequenceD1;                                                       //0x0
    ULONG SequenceD2;                                                       //0x4
    ULONG SequenceD3;                                                       //0x8
}; 