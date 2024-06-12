#pragma once

#include "WinTypes.h"


//0x10 bytes (sizeof)
struct _SID_AND_ATTRIBUTES
{
    VOID* Sid;                                                              //0x0
    ULONG Attributes;                                                       //0x8
}; 