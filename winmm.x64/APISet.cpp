#include <windows.h>
#include "APISet.h"
#include "GUIDUtils.h"
#include <stdio.h>

void APISet::setGUID(GUID* f) {
    guid = *f;
}

bool APISet::matches(GUID* f) {
    return (IsEqualGUIDS(f, &guid));
}

void APISet::performAction(__int64 classptr) {
    if (classptr == 0) {
        printf("Error: classptr is NULL\n");
        return;
    }

    // Get the vtable pointer from the class instance
    __int64 vtablePtr = *(__int64*)classptr;
    if (vtablePtr == 0) {
        printf("Error: vtable pointer is NULL\n");
        return;
    }

    //printf("Performing hook action on classptr: %llx, vtable: %llx\n", classptr, vtablePtr);
    
    for (int i = 0; i < n; i++) {
        // Calculate the address of the function pointer in the vtable
        __int64* targetFuncPtrAddr = (__int64*)(vtablePtr + entries[i].classoffset);

        // Read the current function pointer from vtable
        __int64 currentFuncPtr = *targetFuncPtrAddr;

        // Check if already hooked (compare with our hook function pointer)
        if (currentFuncPtr == entries[i].funcptr) {
            continue;
        }

        // Backup the original function pointer if not already backed up
        entryMutex[i].lock();
        if (entries[i].origfuncptr == 0) {
            entries[i].origfuncptr = currentFuncPtr;
            printf("Backed up original function pointer for %s: %llx\n",
                entries[i].apiname.c_str(), entries[i].origfuncptr);
        }

        // Change memory protection to allow writing to vtable
        DWORD oldProtect;
        if (!VirtualProtect(targetFuncPtrAddr, sizeof(__int64), PAGE_EXECUTE_READWRITE, &oldProtect)) {
            entryMutex[i].unlock();
            printf("Failed to change memory protection for %s (error: %d)\n",
                entries[i].apiname.c_str(), GetLastError());
            continue;
        }

        // Replace the function pointer in vtable
        *targetFuncPtrAddr = entries[i].funcptr;

        // Restore memory protection
        DWORD dummy;
        VirtualProtect(targetFuncPtrAddr, sizeof(__int64), oldProtect, &dummy);
        entryMutex[i].unlock();
        printf("Successfully hooked %s at vtable offset %lld (vtable addr: %llx)\n",
            entries[i].apiname.c_str(), entries[i].classoffset, (__int64)targetFuncPtrAddr);
    }
}

APIEntry createAPIEntry(const std::string& name, __int64 funcptr, __int64 classoffset) {
    APIEntry entry;
    entry.apiname = name;
    entry.funcptr = funcptr;
    entry.classoffset = classoffset;
    entry.origfuncptr = 0; // To be filled later when perform Action
    return entry;
}
