#pragma once

#include "WinTypes.h"


//0x10 bytes (sizeof)
struct _IO_STATUS_BLOCK
{
    union
    {
        LONG Status;                                                        //0x0
        VOID* Pointer;                                                      //0x0
    };
    ULONGLONG Information;                                                  //0x8
}; 