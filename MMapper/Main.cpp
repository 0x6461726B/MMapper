#include <iostream>
#include <string>
#include "common.h"
#include "stub.h"
#include <TlHelp32.h>


DWORD GetProcessIdByName(const char* name)
{
    auto snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe = { sizeof(pe) };

    Process32First(snap, &pe);

    do {
        if (_strcmpi(pe.szExeFile, name) == 0) {
            CloseHandle(snap);
            return pe.th32ProcessID;
        }
    } while (Process32Next(snap, &pe));

    CloseHandle(snap);
    return 0;
}

uint8_t* ReadFileToBuffer(const char* path, size_t& outSize)
{
    auto hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        return nullptr;
    }

    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize)) {
        CloseHandle(hFile);
        return nullptr;
    }

    auto buffer = (uint8_t*)VirtualAlloc(0, fileSize.QuadPart, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    DWORD bytesRead = 0;

    auto result = ReadFile(hFile, buffer, (DWORD)fileSize.QuadPart, &bytesRead, NULL);

    CloseHandle(hFile);

    if (!result || bytesRead != fileSize.QuadPart) {
        VirtualFree(buffer, 0, MEM_RELEASE);
        return nullptr;
    }


    outSize = bytesRead;

    return buffer;
}


bool InjectDll(DWORD pid, const char* dllPath)
{

    size_t outSize;
    auto dll = ReadFileToBuffer(dllPath, outSize);

    auto dos = (PIMAGE_DOS_HEADER)dll;

    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        VirtualFree(dll, 0, MEM_RELEASE);
        return false;
    }

    auto ntHeader = (PIMAGE_NT_HEADERS)(dll + dos->e_lfanew);

    if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
        VirtualFree(dll, 0, MEM_RELEASE);
        return false;
    }

    if ((ntHeader->FileHeader.Characteristics & IMAGE_FILE_DLL) == 0) {
        VirtualFree(dll, 0, MEM_RELEASE);
        return false;
    }


    if (ntHeader->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        VirtualFree(dll, 0, MEM_RELEASE);
        return false;
    }

    auto hProc = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION, 0, pid);

    if (!hProc) {
        VirtualFree(dll, 0, MEM_RELEASE);
        return false;
    }


    void* remoteBase = VirtualAllocEx(hProc, 0, ntHeader->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);


    WriteProcessMemory(hProc, remoteBase, dll, ntHeader->OptionalHeader.SizeOfHeaders, nullptr);

    auto sections = IMAGE_FIRST_SECTION(ntHeader);
    
    for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
        if (sections[i].SizeOfRawData == 0) continue;

        WriteProcessMemory(hProc, (uint8_t*)remoteBase + sections[i].VirtualAddress, dll + sections[i].PointerToRawData, sections[i].SizeOfRawData, nullptr);

    }

    ManualMapData mapData = { 0 };
    mapData.imageBase = (uint8_t*)remoteBase;
    mapData.fnLoadLibraryA = LoadLibraryA;
    mapData.fnGetProcAddress = GetProcAddress;
    mapData.fnRtlAddFunctionTable = RtlAddFunctionTable;
    mapData.fnVirtualProtectEx = VirtualProtectEx;
    mapData.errorCode = SUCCESS;

    size_t stubSize = 0x5000;//(uintptr_t)StubEnd - (uintptr_t)LoaderStub;

    auto total = stubSize + sizeof(ManualMapData);
    void* stubRemote = VirtualAllocEx(hProc, 0, total, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    WriteProcessMemory(hProc, stubRemote, LoaderStub, stubSize, nullptr);
    void* dataRemote = (uint8_t*)stubRemote + stubSize;
    WriteProcessMemory(hProc, dataRemote, &mapData, sizeof(mapData), nullptr);


    auto hThread = CreateRemoteThread(hProc, nullptr, 0, (LPTHREAD_START_ROUTINE)stubRemote, dataRemote, 0, nullptr);

    WaitForSingleObject(hThread, INFINITE);

    ReadProcessMemory(hProc, dataRemote, &mapData, sizeof(mapData), nullptr);
    auto result = mapData.errorCode;
    if (result == SUCCESS) {
        printf("Successfully injected the stub. 0x%lx\n", result);
    }
    else {
        printf("Injection failed, error code: 0x%lx\n", result);
        if (result == LOAD_LIBRARY_FAILED) {
            printf("Missing Dependency: %s\n", mapData.errorData);
        }
        return false;
    }


    VirtualFreeEx(hProc, stubRemote, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProc);
    VirtualFree(dll, 0, MEM_RELEASE);
   

    return result; 
}


int main(int argc, char* argv[])
{
     std::string dllPath;
     std::string targetProcess;
    
     printf("Enter the DLL path: ");
     std::getline(std::cin, dllPath);
     dllPath.erase(std::remove(dllPath.begin(), dllPath.end(), '\"'), dllPath.end()); //make sure "//path//etc" work by removing the quotes
     printf("Enter the target process: ");
     std::getline(std::cin, targetProcess);


     DWORD pid = GetProcessIdByName(targetProcess.c_str());
     if (!pid) {
         printf("Process not found\n");
         system("pause");
         return 1;
     }
    
     if (InjectDll(pid, dllPath.c_str()))
         printf("Injection succeeded!\n");
     else
         printf("Injection failed.\n");


    system("pause");
    return 0;
}