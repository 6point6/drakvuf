#pragma once

#include "WinTypes.h"


//0x10 bytes (sizeof)
struct _PROC_IDLE_SNAP
{
    ULONGLONG Time;                                                         //0x0
    ULONGLONG Idle;                                                         //0x8
}; 