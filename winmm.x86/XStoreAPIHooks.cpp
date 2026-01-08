// Automatically patch xgameruntime.lib linked into game executables
#include <windows.h>
#include "XStoreAPIHooks.h"
#include "GUIDUtils.h"
#include <stdio.h>
#include <Windows.h>
#include <Psapi.h>
#include <Shlwapi.h>
#include <shellapi.h>
#include <vector>
#include <set>
#include <io.h>
#include <fcntl.h>
#include <conio.h>

#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "shell32.lib") 
#define FOREGROUND_YELLOW (FOREGROUND_RED | FOREGROUND_GREEN)
// Global XStore API instance
APISet XStoreAPI;

// 全局变量：存储整个 EXE 映像
std::vector<BYTE> exeFile;
HMODULE exeBaseAddress = nullptr;
char originalExePath[MAX_PATH];

// 记录找到的函数入口位置
struct CallerInfo {
    UINT64 returnAddress;
    UINT64 rva;
    size_t fileOffset;
    const char* apiName;
};
std::vector<CallerInfo> callerInfos;

// 用于去重，避免重复记录同一个调用者
std::set<size_t> recordedOffsets;

// 需要找到的 API 数量
const int REQUIRED_API_COUNT = 3;

typedef struct XStoreGameLicense {
    char skuStoreId[18];
    bool isActive;
    bool isTrialOwnedByThisUser;
    bool isDiscLicense;
    bool isTrial;
    uint32_t trialTimeRemainingInSeconds;
    char trialUniqueId[64];
    time_t expirationDate;
} XStoreGameLicense;

typedef void (*XAsyncCompletionCallback)(void* asyncBlock);
typedef struct XAsyncBlock {
    void* queue;
    void* context;
    XAsyncCompletionCallback callback;
    unsigned internal[sizeof(void*) * 4];
} XAsyncBlock;

// XStoreQueryGameLicenseResult 的补丁代码
/** /
const BYTE patch_GameLicenseResult[] = {
    0x57, 0x48, 0x8B, 0xFA, 0x48, 0xB8, 0x39, 0x50,
    0x35, 0x58, 0x34, 0x51, 0x56, 0x4C, 0x48, 0xAB,
    0x48, 0xC7, 0xC0, 0x43, 0x32, 0x58, 0x52, 0x48,
    0xAB, 0x48, 0xB8, 0x00, 0x00, 0x01, 0x01, 0x00,
    0x00, 0xCC, 0xCC, 0x48, 0xAB, 0x48, 0x33, 0xC0,
    0x48, 0xAB, 0xB9, 0x07, 0x00, 0x00, 0x00, 0xF3,
    0x48, 0xAB, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC, 0xAB,
    0x33, 0xC0, 0xAB, 0x48, 0xB8, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x7F, 0x48, 0xAB, 0x5F,
    0x33, 0xC0, 0xC3
};/**/
BYTE patch_GameLicenseResult[] = {
    0x57,                                           // push rdi 0-1
    0x48, 0x8B, 0xFA,                              // mov rdi, rdx  1-4
    
    // 存储 skuStoreId[0-7]: "9P5X4QVL"
    0x48, 0xB8, // 4-6
    '9', 'P', '5', 'X', '4', 'Q', 'V', 'L',//6-14
    0x48, 0xAB,                                     // stosq 14-16
    
    // 存储 skuStoreId[8-15]: "C2XR\0\0\0\0"
    0x48, 0xB8, // 16-18
    'C', '2', 'X', 'R', 0x00, 0x00, 0x00, 0x00, //18-26
    0x48, 0xAB,                                     // stosq //26-28
    
    // 存储 skuStoreId[16-17] + bool字段: 0x00 0x00 0x01 0x01
    0x48, 0xB8,//28-30
    0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,//30-38
    0x48, 0xAB,                                     // stosq //38-40
    
    // 循环填充 DWORD (4字节) - 填充 trialTimeRemainingInSeconds 到 expirationDate 之前
    0x33, 0xC0,                                     // xor eax, eax //40-42
    0xB9, 0x12, 0x00, 0x00, 0x00,                  // mov ecx, 18 (18个DWORD = 72字节) //42-47
    0xF3, 0xAB,                                     // rep stosd //47-49
    
    // 存储 expirationDate: 0x7FFFFFFFFFFFFFFF
    0x48, 0xB8,//49-51
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F,//51-59
    0x48, 0xAB,                                     // stosq //59-61
    
    0x5F,                                           // pop rdi//61-62
    0x33, 0xC0,                                     // xor eax, eax//62-64
    0xC3                                            // ret//64-65
};
void setSKU(char* sku){
    //sku示例: 9P5X4QVL-C2XR
    memcpy(patch_GameLicenseResult+6,sku,8);
    memcpy(patch_GameLicenseResult+18,sku+8,8);
    memcpy(patch_GameLicenseResult+30,sku+16,2);

}
// XStoreQueryGameLicenseAsync 的补丁代码
const BYTE patch_GameLicenseAsync[] = {
    0x57, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0xFA,
    0x48, 0x33, 0xC0, 0x48, 0xC7, 0x47, 0x18, 0x00,
    0x00, 0x00, 0x00, 0x48, 0x8B, 0xCF, 0x48, 0x8B,
    0x47, 0x10, 0x48, 0x85, 0xC0, 0x74, 0x02, 0xFF,
    0xD0, 0x33, 0xC0, 0x48, 0x83, 0xC4, 0x20, 0x5F,
    0xC3
};
const BYTE patch_RegisterGameLicenseChanged[] = {
    0x33,0xC0,0xC3
};
// 初始化控制台输出
bool InitializeConsole() {
    if (!AllocConsole()) {
        DWORD error = GetLastError();
        if (error != ERROR_ACCESS_DENIED) {
            return false;
        }
    }

    FILE* fpStdout = nullptr;
    FILE* fpStderr = nullptr;
    FILE* fpStdin = nullptr;

    freopen_s(&fpStdout, "CONOUT$", "w", stdout);
    freopen_s(&fpStderr, "CONOUT$", "w", stderr);
    freopen_s(&fpStdin, "CONIN$", "r", stdin);

    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    SetConsoleTitleA("XStore API Patcher - Debug Console");
    system("cls");

    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    printf("========================================\n");
    printf("  XStore API Patcher - Debug Console\n");
    printf("========================================\n\n");
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

    return true;
}

// 带颜色的日志输出
void LogInfo(const char* format, ...) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
    printf("[INFO] ");
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    printf("\n");
}

void LogWarning(const char* format, ...) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    printf("[WARN] ");
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    printf("\n");
}

void LogError(const char* format, ...) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
    printf("[ERROR] ");
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    printf("\n");
}

void LogSuccess(const char* format, ...) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    printf("[SUCCESS] ");
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    printf("\n");
}

// 将 RVA 转换为文件偏移
size_t RvaToFileOffset(UINT64 rva) {
    if (exeFile.empty()) {
        LogError("EXE file not loaded");
        return (size_t)-1;
    }

    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)exeFile.data();
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        LogError("Invalid DOS signature");
        return (size_t)-1;
    }

    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(exeFile.data() + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        LogError("Invalid NT signature");
        return (size_t)-1;
    }

    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(ntHeaders);
    
    // 遍历所有节，找到包含该 RVA 的节
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        UINT64 sectionStart = sections[i].VirtualAddress;
        UINT64 sectionEnd = sectionStart + sections[i].Misc.VirtualSize;
        
        if (rva >= sectionStart && rva < sectionEnd) {
            // 计算在节内的偏移
            UINT64 offsetInSection = rva - sectionStart;
            size_t fileOffset = sections[i].PointerToRawData + offsetInSection;
            
            LogInfo("  RVA 0x%llx found in section '%s' (VA: 0x%llx-0x%llx, File: 0x%x-0x%x)",
                    rva,
                    sections[i].Name,
                    sectionStart,
                    sectionEnd,
                    sections[i].PointerToRawData,
                    sections[i].PointerToRawData + sections[i].SizeOfRawData);
            LogInfo("  File offset: 0x%zx", fileOffset);
            
            return fileOffset;
        }
    }
    
    LogError("RVA 0x%llx not found in any section", rva);
    return (size_t)-1;
}

// 从返回地址往前查找 48 8B C4 指令
size_t FindFunctionStart(void* returnAddress) {
    if (!exeBaseAddress || exeFile.empty()) {
        return (size_t)-1;
    }

    UINT64 retAddr = (UINT64)returnAddress;
    UINT64 baseAddr = (UINT64)exeBaseAddress;
    
    // 检查地址是否在合理范围内
    if (retAddr < baseAddr) {
        LogError("  Return address (0x%llx) is less than base address (0x%llx)", retAddr, baseAddr);
        return (size_t)-1;
    }
    
    // 计算 RVA（使用 64 位无符号运算）
    UINT64 rva = retAddr - baseAddr;
    
    LogInfo("  Return address: 0x%llx, Base: 0x%llx, RVA: 0x%llx", retAddr, baseAddr, rva);
    
    // 检查 RVA 是否合理
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)exeFile.data();
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(exeFile.data() + dosHeader->e_lfanew);
    UINT64 imageSize = ntHeaders->OptionalHeader.SizeOfImage;
    
    if (rva >= imageSize) {
        LogError("  RVA 0x%llx exceeds image size 0x%llx", rva, imageSize);
        LogError("  The module might be loaded at a different base address");
        
        // 尝试从内存中重新获取基地址
        MODULEINFO modInfo;
        if (GetModuleInformation(GetCurrentProcess(), exeBaseAddress, &modInfo, sizeof(modInfo))) {
            UINT64 realBase = (UINT64)modInfo.lpBaseOfDll;
            UINT64 realSize = modInfo.SizeOfImage;
            LogInfo("  Module info: Base=0x%llx, Size=0x%llx", realBase, realSize);
            
            if (realBase != baseAddr) {
                LogWarning("  Base address mismatch! Using 0x%llx instead of 0x%llx", realBase, baseAddr);
                baseAddr = realBase;
                rva = retAddr - baseAddr;
                LogInfo("  Recalculated RVA: 0x%llx", rva);
            }
        }
        
        if (rva >= imageSize) {
            return (size_t)-1;
        }
    }
    
    // 转换为文件偏移
    size_t fileOffset = RvaToFileOffset(rva);
    if (fileOffset == (size_t)-1) {
        LogError("  Failed to convert RVA to file offset");
        return (size_t)-1;
    }
    
    // 从文件偏移往前搜索
    const size_t MAX_SEARCH = 4096;
    size_t searchStart = (fileOffset > MAX_SEARCH) ? (fileOffset - MAX_SEARCH) : 0;
    
    LogInfo("  Searching for function start (48 8B C4) from offset 0x%zx to 0x%zx", fileOffset, searchStart);
    
    for (size_t i = fileOffset; i > searchStart; i--) {
        if (i + 2 < exeFile.size()) {
            if (exeFile[i] == 0x48 && exeFile[i + 1] == 0x8B && exeFile[i + 2] == 0xC4) {
                LogSuccess("  Found function start at file offset: 0x%zx", i);
                return i;
            }
        }
    }
    
    LogWarning("  Function start (48 8B C4) not found");
    return (size_t)-1;
}
/*
ORIGINAL
48 89 5C 24 08 48 89 74
24 18 48 89 54 24 10 57
48 83 EC 20 48 8B FA 48
8B F1 48 8B 12 48 85 D2
75 58 48 8B 7F 08 48 85
FF 74 3A BB FF FF FF FF
8B C3 F0 0F C1 47 08 83
F8 01 75 29 48 8B 07 48
8B CF 48 8B 00 FF 15 ??
?? ?? 06 F0 0F C1 5F 0C
83 FB 01 75 10 48 8B 07
48 8B CF 48 8B 40 08 FF
15 ?? ?? ?? 06 B8 02 00
00 00 48 8B 5C 24 30 48
8B 74 24 40 48 83 C4 20
5F C3 E8 51 01 00 00 90
84 C0 75 58 48 8B 7F 08
48 85 FF 74 3A BB FF FF
FF FF 8B C3 F0 0F C1 47
08 83 F8 01 75 29 48 8B
07 48 8B CF 48 8B 00 FF
15 ?? ?? ?? 06 F0 0F C1
5F 0C 83 FB 01 75 10 48
8B 07 48 8B CF 48 8B 40
08 FF 15 ?? ?? ?? 06 B8
03 00 00 00 48 8B 5C 24
30 48 8B 74 24 40 48 83
C4 20 5F C3 48 8B 1F 80
BE 98 00 00 00 00 0F 85
88 00 00 00 48 8B 03 48
8B CB 48 8B 80 70 02 00
00 FF 15 ?? ?? ?? 06 84
C0 74 71 48 8B 03 BA 01
00 00 00 48 8B CB 48 8B
40 40 FF 15 ?? ?? ?? 06
84 C0 75 58 48 8B 7F 08
48 85 FF 74 3A BB FF FF
FF FF 8B C3 F0 0F C1 47
08 83 F8 01 75 29 48 8B
07 48 8B CF 48 8B 00 FF
15 ?? ?? ?? 06 F0 0F C1
5F 0C 83 FB 01 75 10 48
8B 07 48 8B CF 48 8B 40
08 FF 15 ?? ?? ?? 06 B8
04 00 00 00 48 8B 5C 24
30 48 8B 74 24 40 48 83
C4 20 5F C3 48 8B 7F 08
48 85 FF 74 3A BB FF FF
FF FF 8B C3 F0 0F C1 47
08 83 F8 01 75 29 48 8B
07 48 8B CF 48 8B 00 FF
15 ?? ?? ?? 06 F0 0F C1
5F 0C 83 FB 01 75 10 48
8B 07 48 8B CF 48 8B 40
08 FF 15 ?? ?? ?? 06 33
C0 48 8B 5C 24 30 48 8B
74 24 40 48 83 C4 20 5F
C3
PATCHED
31 C0 C3 */
int16_t originalpattern[]={
    0x48,0x89,0x5C,0x24,0x08,0x48,0x89,0x74,
    0x24,0x18,0x48,0x89,0x54,0x24,0x10,0x57,
    0x48,0x83,0xEC,0x20,0x48,0x8B,0xFA,0x48,
    0x8B,0xF1,0x48,0x8B,0x12,0x48,0x85,0xD2,
    0x75,0x58,0x48,0x8B,0x7F,0x08,0x48,0x85,
    0xFF,0x74,0x3A,0xBB,0xFF,0xFF,0xFF,0xFF,
    0x8B,0xC3,0xF0,0x0F,0xC1,0x47,0x08,0x83,
    0xF8,0x01,0x75,0x29,0x48,0x8B,0x07,0x48,
    0x8B,0xCF,0x48,0x8B,0x00,0xFF,0x15,-1,
    -1,-1,0x06,0xF0,0x0F,0xC1,0x5F,0x0C,
    0x83,0xFB,0x01,0x75,0x10,0x48,0x8B,0x07,
    0x48,0x8B,0xCF,0x48,0x8B,0x40,0x08,0xFF,
    0x15,-1,-1,-1,0x06,0xB8,0x02,0x00,
    0x00,0x00,0x48,0x8B,0x5C,0x24,0x30,0x48,
    0x8B,0x74,0x24,0x40,0x48,0x83,0xC4,0x20,
    0x5F,0xC3,0xE8,0x51,0x01,0x00,0x00,0x90,
    0x84,0xC0,0x75,0x58,0x48,0x8B,0x7F,0x08,
    0x48,0x85,0xFF,0x74,0x3A,0xBB,0xFF,0xFF,
    0xFF,0xFF,0x8B,0xC3,0xF0,0x0F,0xC1,0x47,
    0x08,0x83,0xF8,0x01,0x75,0x29,0x48,0x8B,
    0x07,0x48,0x8B,0xCF,0x48,0x8B,0x00,0xFF,
    0x15,-1,-1,-1,0x06,0xF0,0x0F,0xC1,
    0x5F,0x0C,0x83,0xFB,0x01,0x75,0x10,0x48,
    0x8B,0x07,0x48,0x8B,0xCF,0x48,0x8B,0x40,
    0x08,0xFF,0x15,-1,-1,-1,0x06,0xB8,
    0x03,0x00,0x00,0x00,0x48,0x8B,0x5C,0x24,
    0x30,0x48,0x8B,0x74,0x24,0x40,0x48,0x83,
    0xC4,0x20,0x5F,0xC3,0x48,0x8B,0x1F,0x80,
    0xBE,0x98,0x00,0x00,0x00,0x00,0x0F,0x85,
    0x88,0x00,0x00,0x00,0x48,0x8B,0x03,0x48,
    0x8B,0xCB,0x48,0x8B,0x80,0x70,0x02,0x00,
    0x00,0xFF,0x15,-1,-1,-1,0x06,0x84,
    0xC0,0x74,0x71,0x48,0x8B,0x03,0xBA,0x01,
    0x00,0x00,0x00,0x48,0x8B,0xCB,0x48,0x8B,
    0x40,0x40,0xFF,0x15,-1,-1,-1,0x06,
    0x84,0xC0,0x75,0x58,0x48,0x8B,0x7F,0x08,
    0x48,0x85,0xFF,0x74,0x3A,0xBB,0xFF,0xFF,
    0xFF,0xFF,0x8B,0xC3,0xF0,0x0F,0xC1,0x47,
    0x08,0x83,0xF8,0x01,0x75,0x29,0x48,0x8B,
    0x07,0x48,0x8B,0xCF,0x48,0x8B,0x00,0xFF,
    0x15,-1,-1,-1,0x06,0xF0,0x0F,0xC1,
    0x5F,0x0C,0x83,0xFB,0x01,0x75,0x10,0x48,
    0x8B,0x07,0x48,0x8B,0xCF,0x48,0x8B,0x40,
    0x08,0xFF,0x15,-1,-1,-1,0x06,0xB8,
    0x04,0x00,0x00,0x00,0x48,0x8B,0x5C,0x24,
    0x30,0x48,0x8B,0x74,0x24,0x40,0x48,0x83,
    0xC4,0x20,0x5F,0xC3,0x48,0x8B,0x7F,0x08,
    0x48,0x85,0xFF,0x74,0x3A,0xBB,0xFF,0xFF,
    0xFF,0xFF,0x8B,0xC3,0xF0,0x0F,0xC1,0x47,
    0x08,0x83,0xF8,0x01,0x75,0x29,0x48,0x8B,
    0x07,0x48,0x8B,0xCF,0x48,0x8B,0x00,0xFF,
    0x15,-1,-1,-1,0x06,0xF0,0x0F,0xC1,
    0x5F,0x0C,0x83,0xFB,0x01,0x75,0x10,0x48,
    0x8B,0x07,0x48,0x8B,0xCF,0x48,0x8B,0x40,
    0x08,0xFF,0x15,-1,-1,-1,0x06,0x33,
    0xC0,0x48,0x8B,0x5C,0x24,0x30,0x48,0x8B,
    0x74,0x24,0x40,0x48,0x83,0xC4,0x20,0x5F,
    0xC3
};
char patchpattern[]={
    0x31,0xC0,0xC3
};
void ApplyPaternPatchs(){
    for(size_t i=0;i<exeFile.size()-sizeof(originalpattern);i++){
        bool match=true;
        for(size_t j=0;j<sizeof(originalpattern);j++){
            if(originalpattern[j]==-1){
                continue;
            }
            if(exeFile[i+j]!=(uint8_t)originalpattern[j]){
                match=false;
                break;
            }
        }
        if(match){
            LogInfo("Pattern matched at file offset: 0x%zx", i);
            //应用补丁
            memcpy(&exeFile[i],patchpattern,sizeof(patchpattern));
            LogSuccess("Pattern patch applied successfully at offset: 0x%zx", i);
        }
    };
}
// 应用补丁到 exeFile
bool ApplyPatches() {
    ApplyPaternPatchs();
    if (callerInfos.empty()) {
        LogWarning("No caller info recorded, cannot apply patches");
        return false;
    }
    
    printf("\n");
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    printf("=== Applying Patches ===\n");
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    printf("\n");
    
    for (const auto& info : callerInfos) {
        const BYTE* patchData = nullptr;
        size_t patchSize = 0;
        
        if (strcmp(info.apiName, "XStoreQueryGameLicenseResult") == 0) {
            patchData = patch_GameLicenseResult;
            patchSize = sizeof(patch_GameLicenseResult);
            LogInfo("Patching XStoreQueryGameLicenseResult caller:");
        }
        else if (strcmp(info.apiName, "XStoreQueryGameLicenseAsync") == 0) {
            patchData = patch_GameLicenseAsync;
            patchSize = sizeof(patch_GameLicenseAsync);
            LogInfo("Patching XStoreQueryGameLicenseAsync caller:");
        }else if (strcmp(info.apiName, "XStoreRegisterGameLicenseChanged") == 0) {
            patchData = patch_RegisterGameLicenseChanged;
            patchSize = sizeof(patch_RegisterGameLicenseChanged);
            LogInfo("Patching XStoreRegisterGameLicenseChanged caller:");
        }
        
        if (patchData && patchSize > 0) {
            LogInfo("  RVA: 0x%llx, File offset: 0x%zx, Patch size: %zu bytes", 
                    info.rva, info.fileOffset, patchSize);
            
            // 检查是否有足够的空间
            if (info.fileOffset + patchSize > exeFile.size()) {
                LogError("  Not enough space for patch (need %zu bytes, have %zu bytes)", 
                         patchSize, exeFile.size() - info.fileOffset);
                continue;
            }
            
            // 显示原始字节
            printf("  Original bytes: ");
            for (size_t i = 0; i < min(patchSize, (size_t)16); i++) {
                printf("%02X ", exeFile[info.fileOffset + i]);
            }
            if (patchSize > 16) printf("...");
            printf("\n");
            
            // 应用补丁
            memcpy(&exeFile[info.fileOffset], patchData, patchSize);
            
            // 显示补丁后的字节
            printf("  Patched bytes:  ");
            for (size_t i = 0; i < min(patchSize, (size_t)16); i++) {
                printf("%02X ", exeFile[info.fileOffset + i]);
            }
            if (patchSize > 16) printf("...");
            printf("\n");
            
            LogSuccess("  Patch applied successfully");
        }
    }
    
    return true;
}

// 生成补丁文件路径
void GeneratePatchedFilePath(char* patchedPath, size_t bufferSize) {
    char drive[_MAX_DRIVE];
    char dir[_MAX_DIR];
    char fname[_MAX_FNAME];
    char ext[_MAX_EXT];
    
    _splitpath_s(originalExePath, drive, _MAX_DRIVE, dir, _MAX_DIR, fname, _MAX_FNAME, ext, _MAX_EXT);
    _snprintf_s(patchedPath, bufferSize, _TRUNCATE, "%s%s%s.patched%s", drive, dir, fname, ext);
}

// 将修补后的 EXE 写入到 .patched.exe 文件
bool WriteExeFileToDisk() {
    char patchedPath[MAX_PATH];
    GeneratePatchedFilePath(patchedPath, MAX_PATH);
    
    printf("\n");
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    printf("=== Writing Patched EXE ===\n");
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    printf("\n");
    
    LogInfo("Original file: %s", originalExePath);
    LogInfo("Patched file will be saved to: %s", patchedPath);
    
    // 如果补丁文件已存在，先删除
    if (PathFileExistsA(patchedPath)) {
        LogWarning("Patched file already exists, deleting...");
        if (!DeleteFileA(patchedPath)) {
            LogWarning("Failed to delete existing patched file (error: %d)", GetLastError());
        }
    }
    
    // 打开文件进行写入
    HANDLE hFile = CreateFileA(patchedPath, GENERIC_WRITE, 0, 
                               nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        LogError("Failed to create patched file (error: %d)", GetLastError());
        return false;
    }
    
    // 写入修补后的数据
    DWORD bytesWritten;
    if (!WriteFile(hFile, exeFile.data(), (DWORD)exeFile.size(), &bytesWritten, nullptr) || 
        bytesWritten != exeFile.size()) {
        LogError("Failed to write patched EXE file");
        CloseHandle(hFile);
        return false;
    }
    
    CloseHandle(hFile);
    
    LogSuccess("Patched EXE written successfully (%u bytes)", bytesWritten);
    LogSuccess("Patched file saved to: %s", patchedPath);
    
    printf("\n");
    SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    printf("=== SUCCESS ===\n");
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    printf("You can now use the patched executable:\n");
    printf("  %s\n", patchedPath);
    printf("\nThe original file remains unchanged.\n");
    
    return true;
}

// 创建自动替换脚本
bool CreateReplacementScript() {
    char scriptPath[MAX_PATH];
    char patchedPath[MAX_PATH];
    char dllPath[MAX_PATH];
    char winmmDllPath[MAX_PATH];
    
    // 获取当前 DLL 路径
    HMODULE hCurrentDll = NULL;
    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       (LPCSTR)&CreateReplacementScript, &hCurrentDll);
    
    if (hCurrentDll) {
        GetModuleFileNameA(hCurrentDll, dllPath, MAX_PATH);
    } else {
        LogError("Failed to get current DLL path");
        return false;
    }
    
    // 获取各个文件路径
    GeneratePatchedFilePath(patchedPath, MAX_PATH);
    
    char drive[_MAX_DRIVE];
    char dir[_MAX_DIR];
    _splitpath_s(originalExePath, drive, _MAX_DRIVE, dir, _MAX_DIR, nullptr, 0, nullptr, 0);
    
    // 生成脚本路径
    _snprintf_s(scriptPath, MAX_PATH, _TRUNCATE, "%s%sapply_patch.bat", drive, dir);
    _snprintf_s(winmmDllPath, MAX_PATH, _TRUNCATE, "%s%swinmm.dll", drive, dir);
    
    LogInfo("Creating replacement script: %s", scriptPath);
    
    // 创建 BAT 脚本
    FILE* script = nullptr;
    if (fopen_s(&script, scriptPath, "w") != 0 || !script) {
        LogError("Failed to create script file");
        return false;
    }
    
    // 写入 BAT 脚本内容
    fprintf(script, "@echo off\n");
    fprintf(script, "chcp 65001 >nul\n");
    fprintf(script, "echo ========================================\n");
    fprintf(script, "echo   XStore Patcher - Auto Replacement\n");
    fprintf(script, "echo ========================================\n");
    fprintf(script, "echo.\n");
//use taskkill
    fprintf(script, "echo Closing the game if it is running...\n");
    fprintf(script, "taskkill /F /IM \"%s\" >nul 2>&1\n", PathFindFileNameA(originalExePath));
    //wait for the exe to exit
    fprintf(script, ":waitloop\n");
    fprintf(script, "tasklist /FI \"IMAGENAME eq %s\" 2>NUL | find /I \"%s\" >NUL\n", PathFindFileNameA(originalExePath), PathFindFileNameA(originalExePath));
    fprintf(script, "if not errorlevel 1 (\n");
    fprintf(script, "    timeout /t 1 /nobreak >nul\n");
    fprintf(script, "    goto waitloop\n");
    fprintf(script, ")\n");
    fprintf(script, "echo.\n");
    
    // 备份原文件
    fprintf(script, "echo Creating backup of original file...\n");
    fprintf(script, "if exist \"%s.backup\" (\n", originalExePath);
    fprintf(script, "    echo Backup already exists, skipping...\n");
    fprintf(script, ") else (\n");
    fprintf(script, "    copy /Y \"%s\" \"%s.backup\" >nul\n", originalExePath, originalExePath);
    fprintf(script, "    if errorlevel 1 (\n");
    fprintf(script, "        echo ERROR: Failed to create backup!\n");
    fprintf(script, "        pause\n");
    fprintf(script, "        exit /b 1\n");
    fprintf(script, "    )\n");
    fprintf(script, "    echo Backup created successfully.\n");
    fprintf(script, ")\n");
    fprintf(script, "echo.\n");
    
    // 替换 EXE
    fprintf(script, "echo Replacing original EXE with patched version...\n");
    fprintf(script, "copy /Y \"%s\" \"%s\" >nul\n", patchedPath, originalExePath);
    fprintf(script, "if errorlevel 1 (\n");
    fprintf(script, "    echo ERROR: Failed to replace EXE!\n");
    fprintf(script, "    echo You may need to run this script as Administrator.\n");
    fprintf(script, "    pause\n");
    fprintf(script, "    exit /b 1\n");
    fprintf(script, ")\n");
    fprintf(script, "echo EXE replaced successfully.\n");
    fprintf(script, "echo.\n");
    
    // 删除补丁文件
    fprintf(script, "echo Cleaning up patch files...\n");
    fprintf(script, "del /F /Q \"%s\" 2>nul\n", patchedPath);
    fprintf(script, "echo Patched file deleted.\n");
    fprintf(script, "echo.\n");
    
    // 删除 DLL 文件
    fprintf(script, "echo Removing injected DLLs...\n");
    fprintf(script, "del /F /Q \"%s\" 2>nul\n", dllPath);
    fprintf(script, "if exist \"%s\" (\n", winmmDllPath);
    fprintf(script, "    del /F /Q \"%s\" 2>nul\n", winmmDllPath);
    fprintf(script, ")\n");
    fprintf(script, "echo DLLs removed.\n");
    fprintf(script, "echo.\n");
    
    // 完成
    fprintf(script, "echo ========================================\n");
    fprintf(script, "echo   Patching Complete!\n");
    fprintf(script, "echo ========================================\n");
    fprintf(script, "echo.\n");
    fprintf(script, "echo The game has been successfully patched.\n");
    fprintf(script, "echo You can now run the game normally.\n");
    fprintf(script, "echo.\n");
    fprintf(script, "echo Original file backed up to:\n");
    fprintf(script, "echo   %s.backup\n", originalExePath);
    fprintf(script, "echo.\n");
    
    // 自删除脚本
    fprintf(script, "(goto) 2>nul & del \"%%~f0\"\n");
    
    fclose(script);
    
    LogSuccess("Replacement script created: %s", scriptPath);
    return true;
}

void FinalizeAndExit() {
    printf("\n");
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    printf("=== All Callers Found - Finalizing Patching ===\n");
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    printf("\n");
    
    LogInfo("Total callers recorded: %zu", callerInfos.size());
    
    // 应用补丁
    if (!ApplyPatches()) {
        LogError("Failed to apply patches");
        printf("\nPress any key to exit...");
        _getch();
        exit(1);
    }
    
    // 写入到 .patched.exe
    if (!WriteExeFileToDisk()) {
        LogError("Failed to write patched EXE to disk");
        printf("\nPress any key to exit...");
        _getch();
        exit(1);
    }
    
    printf("\n");
    SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    printf("=== Patching Complete ===\n");
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    printf("\n");
    
    // 创建自动替换脚本
    if (!CreateReplacementScript()) {
        LogError("Failed to create replacement script");
        printf("\nPress any key to exit...");
        _getch();
        exit(1);
    }
    
    // 启动脚本（隐藏窗口）
    char scriptPath[MAX_PATH];
    char drive[_MAX_DRIVE];
    char dir[_MAX_DIR];
_splitpath_s(originalExePath, drive, _MAX_DRIVE, dir, _MAX_DIR, nullptr, 0, nullptr, 0);
_snprintf_s(scriptPath, MAX_PATH, _TRUNCATE, "%s%sapply_patch.bat", drive, dir);

// 构建命令行 - 传递当前进程 PID 给脚本
char cmdLine[MAX_PATH * 2];
_snprintf_s(cmdLine, sizeof(cmdLine), _TRUNCATE, "cmd.exe /C \"%s\"", scriptPath);

STARTUPINFOA si = { 0 };
PROCESS_INFORMATION pi = { 0 };
si.cb = sizeof(si);
si.dwFlags = STARTF_USESHOWWINDOW;
si.wShowWindow = SW_HIDE;  // 隐藏窗口

if (CreateProcessA(
    nullptr,
    cmdLine,
    nullptr,
    nullptr,
    FALSE,
    CREATE_NEW_PROCESS_GROUP | CREATE_BREAKAWAY_FROM_JOB,  // 创建独立进程组，不受父进程影响
    nullptr,
    nullptr,
    &si,
    &pi
)) {
    LogSuccess("Replacement script started successfully");
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
} else {
    LogWarning("Failed to start replacement script automatically (Error:  %lu)", GetLastError());
    LogInfo("Please run the script manually: %s", scriptPath);
}

// 退出程序
exit(0);
}

// 记录调用者信息
void RecordCallerInfo(const char* apiName,void* returnAddress) {
    // 获取返回地址

    
    LogInfo("[%s] Called from: 0x%llx", apiName, (UINT64)returnAddress);
    
    size_t funcStartOffset = FindFunctionStart(returnAddress);
    
    if (funcStartOffset != (size_t)-1) {
        // 检查是否已经记录过这个偏移
        if (recordedOffsets.find(funcStartOffset) != recordedOffsets.end()) {
            LogInfo("  -> Already recorded, skipping");
            return;
        }
        
        recordedOffsets.insert(funcStartOffset);
        
        CallerInfo info;
        info.returnAddress = (UINT64)returnAddress;
        info.rva = (UINT64)returnAddress - (UINT64)exeBaseAddress;
        info.fileOffset = funcStartOffset;
        info.apiName = apiName;
        
        callerInfos.push_back(info);
        
        LogInfo("  -> Caller recorded: RVA=0x%llx, FileOffset=0x%zx", info.rva, info.fileOffset);
        LogInfo("  -> Callers found: %zu/%d", callerInfos.size(), REQUIRED_API_COUNT);
        
    }
}

__int64 __fastcall XStoreQueryGameLicenseResult(__int64 classptr, __int64 a1, __int64 a2) {
    RecordCallerInfo("XStoreQueryGameLicenseResult",_ReturnAddress());
    XStoreAPI.entryMutex[0].lock();
    __int64 ptr = XStoreAPI.entries[0].origfuncptr;
    XStoreAPI.entryMutex[0].unlock();

    // 使用正确的函数指针调用
    XStoreQueryGameLicenseResult_t originalFunc = (XStoreQueryGameLicenseResult_t)ptr;
    __int64 result = originalFunc(classptr, a1, a2);/**/
    XStoreGameLicense* lic = (XStoreGameLicense*)a2;
    LogInfo("Sku ID: %s",lic->skuStoreId);
    setSKU(lic->skuStoreId);
    // 检查是否已经找到所有需要的调用者
    if (callerInfos.size() >= REQUIRED_API_COUNT) {
        LogSuccess("All required callers found! Starting patching process...");
        Sleep(1000);
        FinalizeAndExit();
    }
    return result;    

}

__int64 __fastcall XStoreQueryGameLicenseAsync(__int64 classptr, __int64 a1, __int64 a2) {
    RecordCallerInfo("XStoreQueryGameLicenseAsync",_ReturnAddress());
    XStoreAPI.entryMutex[1].lock();
    __int64 ptr = XStoreAPI.entries[1].origfuncptr;
    XStoreAPI.entryMutex[1].unlock();

    // 使用正确的函数指针调用
    XStoreQueryGameLicenseAsync_t originalFunc = (XStoreQueryGameLicenseAsync_t)ptr;
    __int64 result = originalFunc(classptr, a1, a2);/**/
            // 检查是否已经找到所有需要的调用者
    if (callerInfos.size() >= REQUIRED_API_COUNT) {
        LogSuccess("All required callers found! Starting patching process...");
        Sleep(1000);
        FinalizeAndExit();
    }
    return result;
}
__int64 __fastcall XStoreRegisterGameLicenseChanged(__int64 classptr, __int64 a1, __int64 a2, __int64 a3, __int64 a4, __int64 a5){
    RecordCallerInfo("XStoreQueryGameLicenseAsync",_ReturnAddress());
    return 0;
}
// 从磁盘加载 EXE 文件到内存
bool LoadExeFileToMemory() {
    // 获取当前模块的文件路径
    if (GetModuleFileNameA(nullptr, originalExePath, MAX_PATH) == 0) {
        LogError("Failed to get module file name");
        return false;
    }
    
    // 获取模块基地址
    exeBaseAddress = GetModuleHandleA(nullptr);
    if (!exeBaseAddress) {
        LogError("Failed to get module handle");
        return false;
    }
    
    LogInfo("Loading EXE from: %s", originalExePath);
    LogInfo("Module base address: 0x%llx", (UINT64)exeBaseAddress);
    
    // 打开文件
    HANDLE hFile = CreateFileA(originalExePath, GENERIC_READ, FILE_SHARE_READ, 
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        LogError("Failed to open EXE file (error: %d)", GetLastError());
        return false;
    }
    
    // 获取文件大小
    LARGE_INTEGER fileSize64;
    if (!GetFileSizeEx(hFile, &fileSize64)) {
        LogError("Failed to get file size");
        CloseHandle(hFile);
        return false;
    }
    
    size_t fileSize = (size_t)fileSize64.QuadPart;
    
    // 读取整个文件
    exeFile.resize(fileSize);
    DWORD bytesRead;
    if (!ReadFile(hFile, exeFile.data(), (DWORD)fileSize, &bytesRead, nullptr) || 
        bytesRead != fileSize) {
        LogError("Failed to read EXE file");
        CloseHandle(hFile);
        return false;
    }
    
    CloseHandle(hFile);
    
    LogSuccess("EXE loaded from disk: size=%zu bytes", fileSize);
    
    // 验证 PE 头
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)exeFile.data();
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        LogError("Invalid DOS signature");
        return false;
    }
    
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(exeFile.data() + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        LogError("Invalid NT signature");
        return false;
    }
    
    LogInfo("PE file validated successfully");
    LogInfo("Number of sections: %d", ntHeaders->FileHeader.NumberOfSections);
    LogInfo("Image size in memory: 0x%x", ntHeaders->OptionalHeader.SizeOfImage);
    
    // 显示所有节的信息
    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(ntHeaders);
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        LogInfo("  Section[%d]: %s - VA: 0x%x, Size: 0x%x, FileOffset: 0x%x",
                i,
                sections[i].Name,
                sections[i].VirtualAddress,
                sections[i].Misc.VirtualSize,
                sections[i].PointerToRawData);
    }
    
    return true;
}

void initXStoreAPISet() {
    // 初始化控制台
    if (!InitializeConsole()) {
        // 如果控制台初始化失败，仍然继续执行
    }
    
    LogInfo("Initializing XStore API Hooks...");
    LogInfo("Waiting for %d API callers to be detected...", REQUIRED_API_COUNT);
    
    // 加载 EXE 文件到内存
    if (!LoadExeFileToMemory()) {
        LogError("Failed to load EXE file, patching will not work");
        printf("\nPress any key to exit...");
        _getch();
        exit(1);
    }
    
    ParseGuid("0DD112AC-7C24-448C-B92B-3960FB5BD30C", XStoreAPI.guid);
    APISET_SET_NUM(XStoreAPI, 3);
    XStoreAPI.entries[0] = createAPIEntry("XStoreQueryGameLicenseResult", 
                                          (__int64)&XStoreQueryGameLicenseResult, 232);
    XStoreAPI.entries[1] = createAPIEntry("XStoreQueryGameLicenseAsync", 
                                          (__int64)&XStoreQueryGameLicenseAsync, 224);
    XStoreAPI.entries[2] = createAPIEntry("XStoreRegisterGameLicenseChanged", 
                                          (__int64)&XStoreRegisterGameLicenseChanged, 528);
    LogSuccess("XStore API Hooks initialized");
    printf("\n");
}