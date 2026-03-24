#include "common.h"
#include <intrin.h>

#pragma runtime_checks("", off) // no surprise CRT helpers ( only relevant when building Debug )
#pragma optimize("", off) // disables optimizations - keeps code as is ( without this, we must hardcode the size )


// either __declspec(safebuffers) OR turn off SDL (https://learn.microsoft.com/en-us/cpp/build/reference/sdl-enable-additional-security-checks?view=msvc-170), overrides stack cookie (/GS-) -> injects security cookie in stub -> it crashes
__declspec(safebuffers) void __stdcall LoaderStub(ManualMapData* pData) 
{
    if (!pData)
        return;

    uint8_t* base = pData->imageBase;
    auto fnLoadLibraryA = pData->fnLoadLibraryA;
    auto fnGetProcAddress = pData->fnGetProcAddress;
    auto fnRtlAddFunctionTable = pData->fnRtlAddFunctionTable;
    auto fnVirtualProtectEx = pData->fnVirtualProtectEx;

    auto dosHeader = (IMAGE_DOS_HEADER*)base;

    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        pData->errorCode = INVALID_PE;
        return;
    }


    auto ntHeader = (IMAGE_NT_HEADERS*)(base + dosHeader->e_lfanew);
    auto optHeader = &ntHeader->OptionalHeader;


    auto delta = (uintptr_t)base - optHeader->ImageBase;

    if (delta != 0) {

        auto relocDir = &optHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relocDir->VirtualAddress != 0) {
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
    }

    auto configDirEntry = optHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
    if (configDirEntry.VirtualAddress != 0) {

        auto configDir = (IMAGE_LOAD_CONFIG_DIRECTORY*)((uintptr_t)base + configDirEntry.VirtualAddress);
        auto cookie = (uint64_t*)configDir->SecurityCookie;
        uint64_t newCookie = __rdtsc() & 0x0000FFFFFFFFFFFF;
        if (newCookie == 0x00002B992DDFA232 || newCookie == 0)
            newCookie = 0x0000BAAD0000F00D;

        *cookie = newCookie;
    }

    auto importDir = optHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    if (importDir.VirtualAddress != 0) {
        auto currentEntry = (IMAGE_IMPORT_DESCRIPTOR*)(base + importDir.VirtualAddress);

        while (currentEntry->Name != NULL) {
            auto dllName = (char*)(base + currentEntry->Name);
            auto hMod = fnLoadLibraryA(dllName);

            if (!hMod) {
                pData->errorCode = LOAD_LIBRARY_FAILED;
                for (int j = 0; j < 127 && dllName[j]; j++) pData->errorData[j] = dllName[j];
                return;
            }


            auto originalFirstThunk = (IMAGE_THUNK_DATA*)(base + currentEntry->OriginalFirstThunk);
            auto firstThunk = (IMAGE_THUNK_DATA*)(base + currentEntry->FirstThunk);

            if (!currentEntry->OriginalFirstThunk)
                originalFirstThunk = firstThunk;

            while (originalFirstThunk->u1.AddressOfData) {

                if (originalFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                    firstThunk->u1.Function = (ULONGLONG)fnGetProcAddress(hMod, (LPCSTR)(originalFirstThunk->u1.Ordinal & 0xFFFF));
                }
                else {
                    auto importByName = (IMAGE_IMPORT_BY_NAME*)(base + originalFirstThunk->u1.AddressOfData);
                    firstThunk->u1.Function = (ULONGLONG)fnGetProcAddress(hMod, importByName->Name);
                }

                if (!firstThunk->u1.Function) {
                    pData->errorCode = GET_PROC_ADDRESS_FAILED;
                    return;
                }

                originalFirstThunk++;
                firstThunk++;
            }

            currentEntry++;
        }
    }


    auto TLSDirEntry = optHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (TLSDirEntry.VirtualAddress != 0) {
        auto TLSDir = (IMAGE_TLS_DIRECTORY*)((uintptr_t)base + TLSDirEntry.VirtualAddress);

        using PIMAGE_TLS_CALLBACK = VOID(WINAPI*)(PVOID DllHandle, DWORD Reason, PVOID Reserve);
        auto callbackArray = (PIMAGE_TLS_CALLBACK*)(TLSDir->AddressOfCallBacks);

        if (callbackArray) {
            while (*callbackArray) {
                (*callbackArray)(base, DLL_PROCESS_ATTACH, nullptr);
                callbackArray++;
            }
        }

    }

    auto ExceptDirEntry = optHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

    if (ExceptDirEntry.VirtualAddress != 0) {
        auto runtimeFunctions = (RUNTIME_FUNCTION*)((uintptr_t)base + ExceptDirEntry.VirtualAddress);
        auto count = ExceptDirEntry.Size / sizeof(RUNTIME_FUNCTION);
        fnRtlAddFunctionTable(runtimeFunctions, count, (uintptr_t)base);
    }

    auto sections = IMAGE_FIRST_SECTION(ntHeader);
    for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
        DWORD oldProtect;
        auto characteristics = sections[i].Characteristics;

        DWORD protect = 0;

        bool exec = characteristics & IMAGE_SCN_MEM_EXECUTE;
        bool read = characteristics & IMAGE_SCN_MEM_READ;
        bool write = characteristics & IMAGE_SCN_MEM_WRITE;

        if (exec && read && write)       protect = PAGE_EXECUTE_READWRITE;
        else if (exec && read)           protect = PAGE_EXECUTE_READ;
        else if (exec && write)          protect = PAGE_EXECUTE_WRITECOPY;
        else if (exec)                   protect = PAGE_EXECUTE;
        else if (read && write)          protect = PAGE_READWRITE;
        else if (read)                   protect = PAGE_READONLY;
        else if (write)                  protect = PAGE_WRITECOPY;
        else                             protect = PAGE_NOACCESS;


        if (!fnVirtualProtectEx((HANDLE)-1, base + sections[i].VirtualAddress, sections[i].Misc.VirtualSize, protect, &oldProtect)) {
            pData->errorCode = VIRTUAL_PROTECT_FAILED;
            return;
        }

    }


    if (optHeader->AddressOfEntryPoint) {

        using fnDllMain = BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID);
        auto dllMain = (fnDllMain)(base + optHeader->AddressOfEntryPoint);
        dllMain((HINSTANCE)base, DLL_PROCESS_ATTACH, nullptr);
    }

    auto headerSize = optHeader->SizeOfHeaders;
    DWORD old;
    fnVirtualProtectEx((HANDLE)-1, base, headerSize, PAGE_READWRITE, &old);
    for (int i = 0; i < headerSize; i++) {
        base[i] = 0;
    }
    fnVirtualProtectEx((HANDLE)-1, base, headerSize, PAGE_READONLY, &old);



    pData->errorCode = SUCCESS;

}

void __stdcall StubEnd() {} 