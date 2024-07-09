#pragma once

#include "WinTypes.h"


//0x4 bytes (sizeof)
struct _ETW_BUFFER_CONTEXT
{
    union
    {
        struct
        {
            UCHAR ProcessorNumber;                                          //0x0
            UCHAR Alignment;                                                //0x1
        };
        USHORT ProcessorIndex;                                              //0x0
    };
    USHORT LoggerId;                                                        //0x2
}; 