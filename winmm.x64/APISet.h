#pragma once
#include <Windows.h>
#include <string>
#include <mutex>

// API Entry structure
struct APIEntry {
    std::string apiname;
    __int64 funcptr;
    __int64 origfuncptr;
    __int64 classoffset;//虚函数偏移
};

// APISet class
class APISet {
private:

public:
    int n = 1;
    GUID guid;
    APIEntry* entries;
    std::mutex* entryMutex;
    
    void setGUID(GUID* f);
    bool matches(GUID* f);
    void performAction(__int64 classptr);
};

// Helper function to create API entry
APIEntry createAPIEntry(const std::string& name, __int64 funcptr, __int64 classoffset);
#define APISET_SET_NUM(APISET,NUM)     (APISET).entries = new APIEntry[(NUM)];\
    (APISET).entryMutex = new std::mutex[(NUM)];\
    (APISET).n = (NUM);
    
