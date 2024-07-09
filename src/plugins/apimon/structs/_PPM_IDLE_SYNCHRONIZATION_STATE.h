#pragma once

#include "WinTypes.h"


//0x4 bytes (sizeof)
union _PPM_IDLE_SYNCHRONIZATION_STATE
{
    LONG AsLong;                                                            //0x0
    LONG RefCount:24;                                                       //0x0
    ULONG State:8;                                                          //0x0
}; 