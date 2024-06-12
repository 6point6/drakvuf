#pragma once

#include "WinTypes.h"


//0x4 bytes (sizeof)
enum _ETW_BUFFER_STATE
{
    EtwBufferStateFree = 0,
    EtwBufferStateGeneralLogging = 1,
    EtwBufferStateCSwitch = 2,
    EtwBufferStateFlush = 3,
    EtwBufferStatePendingCompression = 4,
    EtwBufferStateCompressed = 5,
    EtwBufferStatePlaceholder = 6,
    EtwBufferStateMaximum = 7
}; 