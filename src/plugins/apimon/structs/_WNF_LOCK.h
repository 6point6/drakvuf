#pragma once

#include "WinTypes.h"
#include "_EX_PUSH_LOCK.h"

//0x8 bytes (sizeof)
struct _WNF_LOCK
{
    struct _EX_PUSH_LOCK PushLock;                                          //0x0
}; 