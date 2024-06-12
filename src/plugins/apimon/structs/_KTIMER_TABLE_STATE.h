#pragma once

#include "WinTypes.h"


//0x18 bytes (sizeof)
struct _KTIMER_TABLE_STATE
{
    ULONGLONG LastTimerExpiration[2];                                       //0x0
    ULONG LastTimerHand[2];                                                 //0x10
}; 