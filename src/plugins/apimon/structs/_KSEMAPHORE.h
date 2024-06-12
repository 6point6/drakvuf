#pragma once

#include "WinTypes.h"
#include "_DISPATCHER_HEADER.h"

//0x20 bytes (sizeof)
struct _KSEMAPHORE
{
    struct _DISPATCHER_HEADER Header;                                       //0x0
    LONG Limit;                                                             //0x18
}; 