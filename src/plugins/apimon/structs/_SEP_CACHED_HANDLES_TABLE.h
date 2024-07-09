#pragma once

#include "WinTypes.h"
#include "_EX_PUSH_LOCK.h"
#include "_RTL_DYNAMIC_HASH_TABLE.h"

//0x10 bytes (sizeof)
struct _SEP_CACHED_HANDLES_TABLE
{
    struct _EX_PUSH_LOCK Lock;                                              //0x0
    struct _RTL_DYNAMIC_HASH_TABLE* HashTable;                              //0x8
}; 