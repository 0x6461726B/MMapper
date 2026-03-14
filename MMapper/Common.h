#pragma once
#include <Windows.h>
#include <cstdint>
#include <cstdio>


enum ErrorCode : DWORD {
    SUCCESS = 0,
    INVALID_PARAMS = 1,
    INVALID_PE = 2,
    LOAD_LIBRARY_FAILED = 3,
    GET_PROC_ADDRESS_FAILED = 4,
    VIRTUAL_PROTECT_FAILED = 5
};

struct ManualMapData
{
    uint8_t* imageBase;  // where the PE was written in the target
    decltype(&LoadLibraryA)    fnLoadLibraryA;
    decltype(&GetProcAddress)  fnGetProcAddress;
    decltype(&RtlAddFunctionTable) fnRtlAddFunctionTable;
    decltype(&VirtualProtectEx) fnVirtualProtectEx; //virtualprotect resolved to 0x0 but Ex works 
    ErrorCode errorCode;  
    char errorData[128];
};