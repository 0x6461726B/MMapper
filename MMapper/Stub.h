#pragma once
#include "common.h"


void __stdcall LoaderStub(ManualMapData* pData)
{
    if (!pData)
        return;

    uint8_t* base = pData->imageBase;
    auto fnLoadLibraryA = pData->fnLoadLibraryA;
    auto fnGetProcAddress = pData->fnGetProcAddress;

    auto dosHeader = (IMAGE_DOS_HEADER*)base;
    auto ntHeader = (IMAGE_NT_HEADERS*)(base + dosHeader->e_lfanew);

    auto optHeader = &ntHeader->OptionalHeader;


    auto delta = (uintptr_t)base - optHeader->ImageBase;

    if (delta != 0) {

        auto relocDir = &optHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        auto currentBlock = (IMAGE_BASE_RELOCATION*)(base + relocDir->VirtualAddress);
        auto relocEnd = (uint8_t*)currentBlock + relocDir->Size;

        while ((uint8_t*)currentBlock < relocEnd) {

            DWORD entryCount = (currentBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* entries = (WORD*)(currentBlock + 1);

            for (DWORD i = 0; i < entryCount; i++) {
                int type = entries[i] >> 12;
                int offset = entries[i] & 0xFFF;

                if (type == IMAGE_REL_BASED_DIR64) {
                    *(uint64_t*)(base + currentBlock->VirtualAddress + offset) += delta;
                }
                
            }
            currentBlock = (IMAGE_BASE_RELOCATION*)((uint8_t*)currentBlock + currentBlock->SizeOfBlock);

        }

    }

    auto importDir = optHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    auto currentEntry = (IMAGE_IMPORT_DESCRIPTOR*)(base + importDir.VirtualAddress);
    
    while (currentEntry->Name != NULL) {
        auto dllName = (char*)(base + currentEntry->Name);
        auto hMod = fnLoadLibraryA(dllName);

        if (hMod) {
            auto originalFirstThunk = (IMAGE_THUNK_DATA*)(base + currentEntry->OriginalFirstThunk);
            auto firstThunk = (IMAGE_THUNK_DATA*)(base + currentEntry->FirstThunk);
            
            while (originalFirstThunk->u1.AddressOfData) {

                if (originalFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                    firstThunk->u1.Function =  (ULONGLONG)fnGetProcAddress(hMod, (LPCSTR)(originalFirstThunk->u1.Ordinal & 0xFFFF));
                }
                else {
                    auto importByName = (IMAGE_IMPORT_BY_NAME*)(base + originalFirstThunk->u1.AddressOfData);
                    firstThunk->u1.Function = (ULONGLONG)fnGetProcAddress(hMod, importByName->Name);
                }

                originalFirstThunk++;
                firstThunk++;
            }


        }
        currentEntry++;
    }


    // -------------------------------------------------------
    // STEP 4: TLS callbacks (optional but important)
    // -------------------------------------------------------
    // TODO:
    // - Check if IMAGE_DIRECTORY_ENTRY_TLS has a non-zero size
    // - If so, get the IMAGE_TLS_DIRECTORY
    // - The AddressOfCallBacks field points to a null-terminated array
    //   of function pointers (PIMAGE_TLS_CALLBACK)
    // - Call each one: callback(base, DLL_PROCESS_ATTACH, nullptr)
    //
    // Many simple DLLs won't have TLS, so this can be a later addition.
    // But if you're injecting something compiled with __declspec(thread),
    // skipping this = crash.


    if (optHeader->AddressOfEntryPoint) {

        using fnDllMain = BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID);
        auto dllMain = (fnDllMain)(base + optHeader->AddressOfEntryPoint);
        dllMain((HINSTANCE)base, DLL_PROCESS_ATTACH, nullptr);
    }


    pData->success = TRUE;
}

// Marker function — used to calculate the size of LoaderStub.
// WARNING: Compiler can reorder functions. Compile, then verify in a
// disassembler that StubEnd actually comes right after LoaderStub.
// If it doesn't, just hardcode a generous size (e.g., 0x1000).
void __stdcall StubEnd() {}