#pragma once

#include "WinTypes.h"
#include "_KDEVICE_QUEUE.h"
#include "_KEVENT.h"
#include "_IRP.h"
#include "_LIST_ENTRY.h"
#include "_IO_TIMER.h"
#include "_DEVICE_OBJECT.h"
#include "_DEVOBJ_EXTENSION.h"
#include "_KDPC.h"
#include "_VPB.h"
#include "_DRIVER_OBJECT.h"
#include "_WAIT_CONTEXT_BLOCK.h"

//0x150 bytes (sizeof)
struct _DEVICE_OBJECT
{
    SHORT Type;                                                             //0x0
    USHORT Size;                                                            //0x2
    LONG ReferenceCount;                                                    //0x4
    struct _DRIVER_OBJECT* DriverObject;                                    //0x8
    struct _DEVICE_OBJECT* NextDevice;                                      //0x10
    struct _DEVICE_OBJECT* AttachedDevice;                                  //0x18
    struct _IRP* CurrentIrp;                                                //0x20
    struct _IO_TIMER* Timer;                                                //0x28
    ULONG Flags;                                                            //0x30
    ULONG Characteristics;                                                  //0x34
    struct _VPB* Vpb;                                                       //0x38
    VOID* DeviceExtension;                                                  //0x40
    ULONG DeviceType;                                                       //0x48
    CHAR StackSize;                                                         //0x4c
    union
    {
        struct _LIST_ENTRY ListEntry;                                       //0x50
        struct _WAIT_CONTEXT_BLOCK Wcb;                                     //0x50
    } Queue;                                                                //0x50
    ULONG AlignmentRequirement;                                             //0x98
    struct _KDEVICE_QUEUE DeviceQueue;                                      //0xa0
    struct _KDPC Dpc;                                                       //0xc8
    ULONG ActiveThreadCount;                                                //0x108
    VOID* SecurityDescriptor;                                               //0x110
    struct _KEVENT DeviceLock;                                              //0x118
    USHORT SectorSize;                                                      //0x130
    USHORT Spare1;                                                          //0x132
    struct _DEVOBJ_EXTENSION* DeviceObjectExtension;                        //0x138
    VOID* Reserved;                                                         //0x140
}; 