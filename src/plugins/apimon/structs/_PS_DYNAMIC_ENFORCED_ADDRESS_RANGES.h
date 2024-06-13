#pragma once

#include "WinTypes.h"
#include "_EX_PUSH_LOCK.h"
#include "_RTL_AVL_TREE.h"

//0x10 bytes (sizeof)
struct _PS_DYNAMIC_ENFORCED_ADDRESS_RANGES
{
    struct _RTL_AVL_TREE Tree;                                              //0x0
    struct _EX_PUSH_LOCK Lock;                                              //0x8
}; 