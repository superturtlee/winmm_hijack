// Automatically patch xgameruntime.lib linked into game executables
#include <windows.h>
#include "XStoreAPIHooks.h"
#include "GUIDUtils.h"
#include <stdio.h>
#include <stdarg.h>
#include <Shlwapi.h>
#include <vector>
#include <mutex>
#include <io.h>
#include <fcntl.h>
#include <conio.h>

#pragma comment(lib, "Shlwapi.lib")
// Global XStore API instance
APISet XStoreAPI;

// Global variables
std::vector<BYTE> exeFile;
HMODULE exeBaseAddress = nullptr;
char originalExePath[MAX_PATH];
size_t callerInfos[3]={0};

int callersFound = 0;
#define XSTORE_QUERY_GAME_LICENSE_ASYNC_INDEX 0
#define XSTORE_QUERY_GAME_LICENSE_RESULT_INDEX 1
#define XSTORE_REGISTER_GAME_LICENSE_CHANGED_INDEX 2

// Required API count
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
BYTE patch_GameLicenseAsync[] = {
    0x57, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0xFA,
    0x48, 0x33, 0xC0, 0x48, 0xC7, 0x47, 0x18, 0x00,
    0x00, 0x00, 0x00, 0x48, 0x8B, 0xCF, 0x48, 0x8B,
    0x47, 0x10, 0x48, 0x85, 0xC0, 0x74, 0x02, 0xFF,
    0xD0, 0x33, 0xC0, 0x48, 0x83, 0xC4, 0x20, 0x5F,
    0xC3
};
BYTE patch_RegisterGameLicenseChanged[] = {
    0x33,0xC0,0xC3
};

// 将 RVA 转换为文件偏移
size_t RvaToFileOffset(UINT64 rva) {
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)exeFile.data();
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(exeFile.data() + dosHeader->e_lfanew);
    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(ntHeaders);
    
    // 遍历所有节，找到包含该 RVA 的节
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        UINT64 sectionStart = sections[i].VirtualAddress;
        UINT64 sectionEnd = sectionStart + sections[i].Misc.VirtualSize;
        
        if (rva >= sectionStart && rva < sectionEnd) {
            // 计算在节内的偏移
            UINT64 offsetInSection = rva - sectionStart;
            return sections[i].PointerToRawData + offsetInSection;
        }
    }
    
    printf("RVA 0x%llx not found in any section", rva);
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
        return (size_t)-1;
    }
    
    // 计算 RVA（使用 64 位无符号运算）
    UINT64 rva = retAddr - baseAddr;
    
    printf("  Return address: 0x%llx, Base: 0x%llx, RVA: 0x%llx", retAddr, baseAddr, rva);
    
    // 检查 RVA 是否合理
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)exeFile.data();
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(exeFile.data() + dosHeader->e_lfanew);
    UINT64 imageSize = ntHeaders->OptionalHeader.SizeOfImage;
    
    // 转换为文件偏移
    size_t fileOffset = RvaToFileOffset(rva);    
    // 从文件偏移往前搜索
    const size_t MAX_SEARCH = 4096;
    size_t searchStart = (fileOffset > MAX_SEARCH) ? (fileOffset - MAX_SEARCH) : 0;
    
    printf("  Searching for function start (48 8B C4) from offset 0x%zx to 0x%zx", fileOffset, searchStart);
    
    for (size_t i = fileOffset; i > searchStart; i--) {
        if (i + 2 < exeFile.size()) {
            if (exeFile[i] == 0x48 && exeFile[i + 1] == 0x8B && exeFile[i + 2] == 0xC4) {
                printf("  Found function start at file offset: 0x%zx", i);
                return i;
            }
        }
    }
    
    printf("  Function start (48 8B C4) not found");
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
            printf("Pattern matched at file offset: 0x%zx", i);
            //应用补丁
            memcpy(&exeFile[i],patchpattern,sizeof(patchpattern));
            printf("Pattern patch applied successfully at offset: 0x%zx", i);
        }
    };
}
// 应用补丁到 exeFile
bool ApplyPatches() {
    ApplyPaternPatchs();
    printf("=== Applying Patches ===\n");
    BYTE* patch[3];
    patch[XSTORE_QUERY_GAME_LICENSE_ASYNC_INDEX]=patch_GameLicenseAsync;
    patch[XSTORE_QUERY_GAME_LICENSE_RESULT_INDEX]=patch_GameLicenseResult;
    patch[XSTORE_REGISTER_GAME_LICENSE_CHANGED_INDEX]=patch_RegisterGameLicenseChanged;
    for (int i = 0; i < REQUIRED_API_COUNT; i++) {
        size_t patchSize = sizeof(patch[i]);
        if (patch[i] && patchSize > 0) {
            printf("   File offset: 0x%zx, Patch size: %zu bytes", callerInfos[i], patchSize);
            memcpy(&exeFile[callerInfos[i]], patch[i], patchSize);
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
    printf("=== Writing Patched EXE ===\n");
    
    printf("Original file: %s", originalExePath);
    printf("Patched file will be saved to: %s", patchedPath);
    
    // 如果补丁文件已存在，先删除
    if (PathFileExistsA(patchedPath)) {
        printf("Patched file already exists, deleting...");
        if (!DeleteFileA(patchedPath)) {
            printf("Failed to delete existing patched file (error: %d)", GetLastError());
        }
    }
    
    // 打开文件进行写入
    HANDLE hFile = CreateFileA(patchedPath, GENERIC_WRITE, 0, 
                               nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    // 写入修补后的数据
    DWORD bytesWritten;
    WriteFile(hFile, exeFile.data(), (DWORD)exeFile.size(), &bytesWritten, nullptr);
    
    CloseHandle(hFile);
    printf("Patched EXE written successfully (%u bytes)", bytesWritten);
    printf("Patched file saved to: %s", patchedPath);
}

// 创建自动替换脚本
bool CreateReplacementScript() {
    char scriptPath[MAX_PATH];
    char patchedPath[MAX_PATH];
    char dllPath[MAX_PATH];
    char winmmDllPath[MAX_PATH];
    
    // 获取各个文件路径
    GeneratePatchedFilePath(patchedPath, MAX_PATH);
    
    char drive[_MAX_DRIVE];
    char dir[_MAX_DIR];
    _splitpath_s(originalExePath, drive, _MAX_DRIVE, dir, _MAX_DIR, nullptr, 0, nullptr, 0);
    
    // 生成脚本路径
    _snprintf_s(scriptPath, MAX_PATH, _TRUNCATE, "%s%sapply_patch.bat", drive, dir);
    _snprintf_s(winmmDllPath, MAX_PATH, _TRUNCATE, "%s%swinmm.dll", drive, dir);
    
    printf("Creating replacement script: %s", scriptPath);
    
    // 创建 BAT 脚本
    FILE* script = nullptr;
    fopen_s(&script, scriptPath, "w");
    
    // 写入 BAT 脚本内容
    fprintf(script, "@echo off\n");
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
    
    // 替换 EXE
    fprintf(script, "copy /Y \"%s\" \"%s\" >nul\n", patchedPath, originalExePath);
    
    // 删除补丁文件
    fprintf(script, "del /F /Q \"%s\" 2>nul\n", patchedPath);

    
    // 删除 DLL 文件
    fprintf(script, "del /F /Q \"%s\" 2>nul\n", winmmDllPath);
    
    // 自删除脚本
    fprintf(script, "(goto) 2>nul & del \"%%~f0\"\n");
    
    fclose(script);
    
    printf("Replacement script created: %s", scriptPath);
    return true;
}

void FinalizeAndExit() {
    // Prevent multiple simultaneous calls
    printf("Total callers recorded: %zu", callerInfos.size());
    
    // 应用补丁
    ApplyPatches();
    
    // 写入到 .patched.exe
    WriteExeFileToDisk();
    
    // 创建自动替换脚本
    CreateReplacementScript();
    
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
    printf("Replacement script started successfully");
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
} else {
    printf("Failed to start replacement script automatically (Error:  %lu)", GetLastError());
    printf("Please run the script manually: %s", scriptPath);
}

// 退出程序
exit(0);
}

// 记录调用者信息
void RecordCallerInfo(int index,void* returnAddress) {
    // 获取返回地址

    
    printf("[%d] Called from: 0x%llx", index, (UINT64)returnAddress);
    
    size_t funcStartOffset = FindFunctionStart(returnAddress);
    
    if (funcStartOffset != (size_t)-1) {
        // 检查是否已经记录过这个偏移
        if (callerInfos[index]) {
            printf("  -> Already recorded, skipping");
            return;
        }
        
        callerInfos[index] = funcStartOffset;
        
        callersFound++;
        
        printf("  -> Callers found: %zu/%d", callersFound, REQUIRED_API_COUNT);
        
    }
}

__int64 __fastcall XStoreQueryGameLicenseResult(__int64 classptr, __int64 a1, __int64 a2) {
    RecordCallerInfo(XSTORE_QUERY_GAME_LICENSE_RESULT_INDEX,_ReturnAddress());
    XStoreAPI.entryMutex[0].lock();
    __int64 ptr = XStoreAPI.entries[0].origfuncptr;
    XStoreAPI.entryMutex[0].unlock();

    // 使用正确的函数指针调用
    XStoreQueryGameLicenseResult_t originalFunc = (XStoreQueryGameLicenseResult_t)ptr;
    __int64 result = originalFunc(classptr, a1, a2);/**/
    XStoreGameLicense* lic = (XStoreGameLicense*)a2;
    printf("Sku ID: %s",lic->skuStoreId);
    setSKU(lic->skuStoreId);
    // 检查是否已经找到所有需要的调用者
    if (callersFound >= REQUIRED_API_COUNT) {
        printf("All required callers found! Starting patching process...");
        FinalizeAndExit();
    }
    return result;    

}

__int64 __fastcall XStoreQueryGameLicenseAsync(__int64 classptr, __int64 a1, __int64 a2) {
    RecordCallerInfo(XSTORE_QUERY_GAME_LICENSE_ASYNC_INDEX,_ReturnAddress());
    XStoreAPI.entryMutex[1].lock();
    __int64 ptr = XStoreAPI.entries[1].origfuncptr;
    XStoreAPI.entryMutex[1].unlock();

    // 使用正确的函数指针调用
    XStoreQueryGameLicenseAsync_t originalFunc = (XStoreQueryGameLicenseAsync_t)ptr;
    __int64 result = originalFunc(classptr, a1, a2);/**/
            // 检查是否已经找到所有需要的调用者
    if (callersFound >= REQUIRED_API_COUNT) {
        printf("All required callers found! Starting patching process...");
        FinalizeAndExit();
    }
    return result;
}
__int64 __fastcall XStoreRegisterGameLicenseChanged(__int64 classptr, __int64 a1, __int64 a2, __int64 a3, __int64 a4, __int64 a5){
    RecordCallerInfo(XSTORE_REGISTER_GAME_LICENSE_CHANGED_INDEX,_ReturnAddress());
    if (callersFound >= REQUIRED_API_COUNT) {
        printf("All required callers found! Starting patching process...");
        FinalizeAndExit();
    }
    return 0;
}
// 从磁盘加载 EXE 文件到内存
bool LoadExeFileToMemory() {
    // 获取当前模块的文件路径
    if (GetModuleFileNameA(nullptr, originalExePath, MAX_PATH) == 0) {
        printf("Failed to get module file name");
        return false;
    }
    
    // 获取模块基地址
    exeBaseAddress = GetModuleHandleA(nullptr);
    
    printf("Loading EXE from: %s", originalExePath);
    printf("Module base address: 0x%llx", (UINT64)exeBaseAddress);
    
    // 打开文件
    HANDLE hFile = CreateFileA(originalExePath, GENERIC_READ, FILE_SHARE_READ, 
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Failed to open EXE file (error: %d)", GetLastError());
        return false;
    }
    
    // 获取文件大小
    LARGE_INTEGER fileSize64;
    GetFileSizeEx(hFile, &fileSize64);
    
    size_t fileSize = (size_t)fileSize64.QuadPart;
    
    // 读取整个文件
    exeFile.resize(fileSize);
    DWORD bytesRead;
    ReadFile(hFile, exeFile.data(), (DWORD)fileSize, &bytesRead, nullptr);
    CloseHandle(hFile);
    
    printf("EXE loaded from disk: size=%zu bytes", fileSize);
    return true;
}

void initXStoreAPISet() {
    printf("Initializing XStore API Hooks...");
    printf("Waiting for %d API callers to be detected...", REQUIRED_API_COUNT);
    
    // Load EXE file into memory
    if (!LoadExeFileToMemory()) {
        printf("Failed to load EXE file, patching will not work");
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
    printf("XStore API Hooks initialized");
    printf("\n");
}