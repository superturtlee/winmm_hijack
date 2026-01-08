#pragma once
#include <Windows.h>
#include <string>

// Helper function to compare GUIDs
BOOL IsEqualGUIDS(const GUID* guid1, const GUID* guid2);

// Helper function to parse GUID from string
bool ParseGuid(const std::string& str, GUID& guid);

// Helper function to print GUID
void PrintGUID(const char* name, GUID* guid);
