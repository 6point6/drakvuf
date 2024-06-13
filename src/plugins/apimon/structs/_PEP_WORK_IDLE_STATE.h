#pragma once

#include "WinTypes.h"
#include "POHANDLE__.h"

//0x10 bytes (sizeof)
struct _PEP_WORK_IDLE_STATE
{
    struct POHANDLE__* DeviceHandle;                                        //0x0
    ULONG Component;                                                        //0x8
    ULONG State;                                                            //0xc
}; 