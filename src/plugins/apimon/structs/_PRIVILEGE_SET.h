#pragma once

#include "WinTypes.h"
#include "_LUID_AND_ATTRIBUTES.h"

//0x14 bytes (sizeof)
struct _PRIVILEGE_SET
{
    ULONG PrivilegeCount;                                                   //0x0
    ULONG Control;                                                          //0x4
    struct _LUID_AND_ATTRIBUTES Privilege[1];                               //0x8
}; 