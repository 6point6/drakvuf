#pragma once

#include "WinTypes.h"


//0x4 bytes (sizeof)
enum _IRQ_PRIORITY
{
    IrqPriorityUndefined = 0,
    IrqPriorityLow = 1,
    IrqPriorityNormal = 2,
    IrqPriorityHigh = 3
}; 