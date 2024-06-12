#pragma once

#include "WinTypes.h"
#include "_CONTEXT.h"
#include "_KSPECIAL_REGISTERS.h"

//0x5c0 bytes (sizeof)
struct _KPROCESSOR_STATE
{
    struct _KSPECIAL_REGISTERS SpecialRegisters;                            //0x0
    struct _CONTEXT ContextFrame;                                           //0xf0
}; 