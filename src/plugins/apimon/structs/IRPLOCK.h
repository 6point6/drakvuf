#pragma once

#include "WinTypes.h"


//0x4 bytes (sizeof)
enum IRPLOCK
{
    IRPLOCK_CANCELABLE = 0,
    IRPLOCK_CANCEL_STARTED = 1,
    IRPLOCK_CANCEL_COMPLETE = 2,
    IRPLOCK_COMPLETED = 3
}; 