#pragma once

#include "WinTypes.h"
#include "_OBJECT_DIRECTORY.h"
#include "_DEVICE_MAP.h"
#include "_EX_PUSH_LOCK.h"
#include "_OBJECT_DIRECTORY_ENTRY.h"

//0x158 bytes (sizeof)
struct _OBJECT_DIRECTORY
{
    struct _OBJECT_DIRECTORY_ENTRY* HashBuckets[37];                        //0x0
    struct _EX_PUSH_LOCK Lock;                                              //0x128
    struct _DEVICE_MAP* DeviceMap;                                          //0x130
    struct _OBJECT_DIRECTORY* ShadowDirectory;                              //0x138
    VOID* NamespaceEntry;                                                   //0x140
    VOID* SessionObject;                                                    //0x148
    ULONG Flags;                                                            //0x150
    ULONG SessionId;                                                        //0x154
}; 