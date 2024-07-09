#pragma once

#include "WinTypes.h"


//0x10 bytes (sizeof)
struct _CLIENT_ID
{
    VOID* UniqueProcess;                                                    //0x0
    VOID* UniqueThread;                                                     //0x8
}; 