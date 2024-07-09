#pragma once

#include "WinTypes.h"


//0x8 bytes (sizeof)
struct _HANDLE_TABLE_ENTRY_INFO
{
    ULONG AuditMask;                                                        //0x0
    ULONG MaxRelativeAccessMask;                                            //0x4
}; 