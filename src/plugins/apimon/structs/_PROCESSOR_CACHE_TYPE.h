#pragma once

#include "WinTypes.h"


//0x4 bytes (sizeof)
enum _PROCESSOR_CACHE_TYPE
{
    CacheUnified = 0,
    CacheInstruction = 1,
    CacheData = 2,
    CacheTrace = 3
}; 