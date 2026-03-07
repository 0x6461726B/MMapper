#pragma once
#pragma once
#include <Windows.h>
#include <cstdint>
#include <cstdio>

// ============================================================================
// This struct gets written into the target process alongside your stub.
// The stub receives a pointer to this and uses it to do all fixups.
//
// Why function pointers? The stub runs in a remote process — it can't call
// your injector's imports. These two are enough to bootstrap everything else.
// ============================================================================
struct ManualMapData
{
    uint8_t* imageBase;  // where the PE was written in the target

    // You need to resolve these from kernel32 before injection.
    // They're your stub's "bootstrap" — with these two, it can load
    // any other DLL and resolve any other function.
    decltype(&LoadLibraryA)    fnLoadLibraryA;
    decltype(&GetProcAddress)  fnGetProcAddress;

    // TODO: Think about what other function pointers your stub might need.
    // For example:
    //   - RtlAddFunctionTable (for x64 exception handling)
    //   - VirtualProtect (if you want to set proper section protections)
    // Add them here as you discover you need them.

    BOOL success;  // stub sets this to TRUE if everything worked
};