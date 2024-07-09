#pragma once

#include "WinTypes.h"


//0x10 bytes (sizeof)
struct _PO_DIAG_STACK_RECORD
{
    ULONG StackDepth;                                                       //0x0
    VOID* Stack[1];                                                         //0x8
}; 