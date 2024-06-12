#pragma once

#include "WinTypes.h"
#include "_LIST_ENTRY.h"

//0x18 bytes (sizeof)
struct _KDEVICE_QUEUE_ENTRY
{
    struct _LIST_ENTRY DeviceListEntry;                                     //0x0
    ULONG SortKey;                                                          //0x10
    UCHAR Inserted;                                                         //0x14
}; 