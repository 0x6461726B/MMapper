#pragma once
#pragma once
#include <Windows.h>
#include <cstdint>
#include <cstdio>



struct ManualMapData
{
    uint8_t* imageBase;  // where the PE was written in the target
    decltype(&LoadLibraryA)    fnLoadLibraryA;
    decltype(&GetProcAddress)  fnGetProcAddress;
    decltype(&RtlAddFunctionTable) fnRtlAddFunctionTable;
    decltype(&VirtualProtectEx) fnVirtualProtectEx; //virtualprotect resolved to 0x0 but Ex works 
    BOOL success;  
};