#pragma once

#include "WinTypes.h"
#include "_EPARTITION.h"

//0x8 bytes (sizeof)
struct _ETW_PARTITION_CONTEXT
{
    struct _EPARTITION* Partition;                                          //0x0
}; 