#pragma once

#include "WinTypes.h"
#include "_LUID_AND_ATTRIBUTES.h"

//0x10 bytes (sizeof)
struct _TOKEN_PRIVILEGES
{
    ULONG PrivilegeCount;                                                   //0x0
    struct _LUID_AND_ATTRIBUTES Privileges[1];                              //0x4
}; 