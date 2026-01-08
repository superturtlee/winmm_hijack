#include <windows.h>
#include "GUIDUtils.h"
#include <stdio.h>
#include <string.h>

// Helper function to compare GUIDs
BOOL IsEqualGUIDS(const GUID* guid1, const GUID* guid2) {
    if (guid1 == nullptr || guid2 == nullptr) {
        return FALSE;
    }
    return (guid1->Data1 == guid2->Data1 &&
        guid1->Data2 == guid2->Data2 &&
        guid1->Data3 == guid2->Data3 &&
        memcmp(guid1->Data4, guid2->Data4, 8) == 0);
}

// Helper function to parse GUID from string
bool ParseGuid(const std::string& str, GUID& guid) {
    unsigned int d1, d2, d3;
    unsigned int d4[8];
    int n = sscanf_s(str.c_str(),
        "%8x-%4x-%4x-%2x%2x-%2x%2x%2x%2x%2x%2x",
        &d1, &d2, &d3, &d4[0], &d4[1], &d4[2], &d4[3], &d4[4], &d4[5], &d4[6], &d4[7]);
    if (n == 11) {
        guid.Data1 = d1;
        guid.Data2 = d2;
        guid.Data3 = d3;
        for (int i = 0; i < 8; ++i)
            guid.Data4[i] = static_cast<unsigned char>(d4[i]);
        return true;
    }
    return false;
}

// Helper function to print GUID
void PrintGUID(const char* name, GUID* guid) {
    if (guid == nullptr) {
        printf("%s: NULL\n", name);
        return;
    }

    printf("%s: {%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}\n",
        name,
        guid->Data1,
        guid->Data2,
        guid->Data3,
        guid->Data4[0], guid->Data4[1],
        guid->Data4[2], guid->Data4[3],
        guid->Data4[4], guid->Data4[5],
        guid->Data4[6], guid->Data4[7]);
}
