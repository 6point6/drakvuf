#pragma once

#include "WinTypes.h"
#include "_KTHREAD.h"
#include "_EX_PUSH_LOCK.h"

//0x10 bytes (sizeof)
struct _POP_RW_LOCK
{
    struct _EX_PUSH_LOCK Lock;                                              //0x0
    struct _KTHREAD* Thread;                                                //0x8
}; 