#pragma once

#include "WinTypes.h"
// #include "_PPM_SELECTION_MENU.h"

//0x18 bytes (sizeof)
struct _PPM_SELECTION_DEPENDENCY
{
    ULONG Processor;                                                        //0x0
    struct _PPM_SELECTION_MENU
    {
        ULONG Count;                                                            //0x0
        struct _PPM_SELECTION_MENU_ENTRY
        {
            UCHAR StrictDependency;                                                 //0x0
            UCHAR InitiatingState;                                                  //0x1
            UCHAR DependentState;                                                   //0x2
            ULONG StateIndex;                                                       //0x4
            ULONG Dependencies;                                                     //0x8
            struct _PPM_SELECTION_DEPENDENCY* DependencyList;                       //0x10
        }; 
        struct _PPM_SELECTION_MENU_ENTRY* Entries;                              //0x8
    }; 
    struct _PPM_SELECTION_MENU Menu;                                        //0x8
};