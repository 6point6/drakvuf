#pragma once

#include "WinTypes.h"
#include "_MMSUPPORT_INSTANCE.h"
#include "_MMSUPPORT_SHARED.h"

//0x140 bytes (sizeof)
struct _MMSUPPORT_FULL
{
    struct _MMSUPPORT_INSTANCE Instance;                                    //0x0
    struct _MMSUPPORT_SHARED Shared;                                        //0xc0
}; 