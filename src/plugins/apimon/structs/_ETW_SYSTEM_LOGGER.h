#pragma once

#include "WinTypes.h"


//0x2 bytes (sizeof)
struct _ETW_SYSTEM_LOGGER
{
    UCHAR LoggerId;                                                         //0x0
    UCHAR ClockType;                                                        //0x1
}; 