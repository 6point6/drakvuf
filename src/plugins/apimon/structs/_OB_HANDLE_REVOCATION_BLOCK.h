#pragma once

#include "WinTypes.h"
#include "_LIST_ENTRY.h"
#include "_EX_PUSH_LOCK.h"
#include "_EX_RUNDOWN_REF.h"

//0x20 bytes (sizeof)
struct _OB_HANDLE_REVOCATION_BLOCK
{
    struct _LIST_ENTRY RevocationInfos;                                     //0x0
    struct _EX_PUSH_LOCK Lock;                                              //0x10
    struct _EX_RUNDOWN_REF Rundown;                                         //0x18
}; 