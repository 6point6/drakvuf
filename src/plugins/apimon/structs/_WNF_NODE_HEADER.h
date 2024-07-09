#pragma once

#include "WinTypes.h"


//0x4 bytes (sizeof)
struct _WNF_NODE_HEADER
{
    USHORT NodeTypeCode;                                                    //0x0
    USHORT NodeByteSize;                                                    //0x2
}; 