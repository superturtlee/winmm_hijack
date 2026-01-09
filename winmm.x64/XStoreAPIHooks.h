#pragma once
#include "APISet.h"

// Global XStore API instance
extern APISet XStoreAPI;

// Function typedefs for XStore hooks
typedef __int64(__fastcall* XStoreQueryGameLicenseAsync_t)(__int64, __int64, __int64);
typedef __int64(__fastcall* XStoreQueryGameLicenseResult_t)(__int64, __int64, __int64);
typedef __int64(__fastcall* XStoreRegisterGameLicenseChanged_t)(__int64, __int64, __int64, __int64, __int64,__int64);
// XStore hook functions
__int64 __fastcall XStoreQueryGameLicenseAsync(__int64 classptr, __int64 a1, __int64 a2);
__int64 __fastcall XStoreQueryGameLicenseResult(__int64 classptr, __int64 a1, __int64 a2);
__int64 __fastcall XStoreRegisterGameLicenseChanged(__int64 classptr, __int64 a1, __int64 a2, __int64 a3, __int64 a4, __int64 a5);
// Initialize console
bool InitializeConsole();
// Initialize XStore API Set
void initXStoreAPISet();
