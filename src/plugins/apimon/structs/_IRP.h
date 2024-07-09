#pragma once

#include "WinTypes.h"
#include "_ETHREAD.h"
#include "_MDL.h"
#include "_KEVENT.h"
#include "_LARGE_INTEGER.h"
#include "_IRP.h"
#include "_LIST_ENTRY.h"
#include "_DEVICE_OBJECT.h"
#include "_KDEVICE_QUEUE_ENTRY.h"
#include "_IO_STATUS_BLOCK.h"
#include "_FILE_OBJECT.h"
#include "_KAPC.h"
#include "_IO_STACK_LOCATION.h"

//0xd0 bytes (sizeof)
struct _IRP
{
    SHORT Type;                                                             //0x0
    USHORT Size;                                                            //0x2
    struct _MDL* MdlAddress;                                                //0x8
    ULONG Flags;                                                            //0x10
    union
    {
        struct _IRP* MasterIrp;                                             //0x18
        LONG IrpCount;                                                      //0x18
        VOID* SystemBuffer;                                                 //0x18
    } AssociatedIrp;                                                        //0x18
    struct _LIST_ENTRY ThreadListEntry;                                     //0x20
    struct _IO_STATUS_BLOCK IoStatus;                                       //0x30
    CHAR RequestorMode;                                                     //0x40
    UCHAR PendingReturned;                                                  //0x41
    CHAR StackCount;                                                        //0x42
    CHAR CurrentLocation;                                                   //0x43
    UCHAR Cancel;                                                           //0x44
    UCHAR CancelIrql;                                                       //0x45
    CHAR ApcEnvironment;                                                    //0x46
    UCHAR AllocationFlags;                                                  //0x47
    struct _IO_STATUS_BLOCK* UserIosb;                                      //0x48
    struct _KEVENT* UserEvent;                                              //0x50
    union
    {
        struct
        {
            union
            {
                VOID (*UserApcRoutine)(VOID* arg1, struct _IO_STATUS_BLOCK* arg2, ULONG arg3); //0x58
                VOID* IssuingProcess;                                       //0x58
            };
            VOID* UserApcContext;                                           //0x60
        } AsynchronousParameters;                                           //0x58
        union _LARGE_INTEGER AllocationSize;                                //0x58
    } Overlay;                                                              //0x58
    VOID (*CancelRoutine)(struct _DEVICE_OBJECT* arg1, struct _IRP* arg2);  //0x68
    VOID* UserBuffer;                                                       //0x70
    union
    {
        struct
        {
            union
            {
                struct _KDEVICE_QUEUE_ENTRY DeviceQueueEntry;               //0x78
                VOID* DriverContext[4];                                     //0x78
            };
            struct _ETHREAD* Thread;                                        //0x98
            CHAR* AuxiliaryBuffer;                                          //0xa0
            struct _LIST_ENTRY ListEntry;                                   //0xa8
            union
            {
                struct _IO_STACK_LOCATION* CurrentStackLocation;            //0xb8
                ULONG PacketType;                                           //0xb8
            };
            struct _FILE_OBJECT* OriginalFileObject;                        //0xc0
        } Overlay;                                                          //0x78
        struct _KAPC Apc;                                                   //0x78
        VOID* CompletionKey;                                                //0x78
    } Tail;                                                                 //0x78
}; 