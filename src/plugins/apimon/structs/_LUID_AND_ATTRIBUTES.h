#pragma once

#include "WinTypes.h"
#include "_LUID.h"

//0xc bytes (sizeof)
struct _LUID_AND_ATTRIBUTES
{
    struct _LUID Luid;                                                      //0x0
    ULONG Attributes;                                                       //0x8
}; 