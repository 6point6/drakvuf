#pragma once

#include "WinTypes.h"
#include "_IO_REMOVE_LOCK_COMMON_BLOCK.h"

//0x20 bytes (sizeof)
struct _IO_REMOVE_LOCK
{
    struct _IO_REMOVE_LOCK_COMMON_BLOCK Common;                             //0x0
}; 