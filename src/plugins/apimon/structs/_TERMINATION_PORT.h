#pragma once

#include "WinTypes.h"
#include "_TERMINATION_PORT.h"

//0x10 bytes (sizeof)
struct _TERMINATION_PORT
{
    struct _TERMINATION_PORT* Next;                                         //0x0
    VOID* Port;                                                             //0x8
}; 