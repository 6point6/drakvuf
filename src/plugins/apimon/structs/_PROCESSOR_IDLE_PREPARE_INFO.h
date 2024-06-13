#pragma once

#include "WinTypes.h"
#include "_PROCESSOR_IDLE_DEPENDENCY.h"
#include "_PROCESSOR_IDLE_CONSTRAINTS.h"

//0x58 bytes (sizeof)
struct _PROCESSOR_IDLE_PREPARE_INFO
{
    VOID* Context;                                                          //0x0
    struct _PROCESSOR_IDLE_CONSTRAINTS Constraints;                         //0x8
    ULONG DependencyCount;                                                  //0x38
    ULONG DependencyUsed;                                                   //0x3c
    struct _PROCESSOR_IDLE_DEPENDENCY* DependencyArray;                     //0x40
    ULONG PlatformIdleStateIndex;                                           //0x48
    ULONG ProcessorIdleStateIndex;                                          //0x4c
    ULONG IdleSelectFailureMask;                                            //0x50
}; 