#pragma once

#include "WinTypes.h"


//0x8 bytes (sizeof)
union _TIMELINE_BITMAP
{
    ULONGLONG Value;                                                        //0x0
    struct
    {
        ULONG EndTime;                                                      //0x0
    };
    ULONG Bitmap;                                                           //0x4
}; 