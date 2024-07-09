#pragma once

#include "WinTypes.h"


//0x4 bytes (sizeof)
enum _PROCESSOR_PRESENCE
{
    ProcessorPresenceNt = 0,
    ProcessorPresenceHv = 1,
    ProcessorPresenceHidden = 2
}; 