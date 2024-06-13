#pragma once

#include "WinTypes.h"
#include "_CM_FULL_RESOURCE_DESCRIPTOR.h"

//0x28 bytes (sizeof)
struct _CM_RESOURCE_LIST
{
    ULONG Count;                                                            //0x0
    struct _CM_FULL_RESOURCE_DESCRIPTOR List[1];                            //0x4
}; 