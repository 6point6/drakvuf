#pragma once

#include "WinTypes.h"
#include "_OBJECT_DIRECTORY.h"
#include "_EJOB.h"

//0x48 bytes (sizeof)
struct _DEVICE_MAP
{
    struct _OBJECT_DIRECTORY* DosDevicesDirectory;                          //0x0
    struct _OBJECT_DIRECTORY* GlobalDosDevicesDirectory;                    //0x8
    VOID* DosDevicesDirectoryHandle;                                        //0x10
    volatile LONG ReferenceCount;                                           //0x18
    ULONG DriveMap;                                                         //0x1c
    UCHAR DriveType[32];                                                    //0x20
    struct _EJOB* ServerSilo;                                               //0x40
}; 