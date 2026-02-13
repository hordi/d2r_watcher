#define WIN32_LEAN_AND_MEAN
#undef UNICODE
#undef _UNICODE

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <string>

#pragma comment(lib, "Psapi.lib")

typedef LONG NTSTATUS;
#define SystemHandleInformation 16
#define ObjectNameInformation 1
#define ObjectTypeInformation 2

using namespace std;

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
using NtQuerySystemInformation_t = NTSTATUS(NTAPI*)(ULONG, PVOID, ULONG, PULONG);

struct SYSTEM_HANDLE {
    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
};

struct SYSTEM_HANDLE_INFORMATION {
    ULONG HandleCount;
    SYSTEM_HANDLE Handles[1];
};

struct UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
};

extern "C" NTSTATUS NTAPI NtQuerySystemInformation(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

extern "C" NTSTATUS NTAPI NtQueryObject(
    HANDLE Handle,
    ULONG ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength
);

string getLastFolderName(DWORD pid)
{
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return {};

    char path[MAX_PATH] = { 0 };
    if (!GetModuleFileNameExA(hProcess, NULL, path, MAX_PATH)) {
        CloseHandle(hProcess);
        return {};
    }
    CloseHandle(hProcess);

    string fullPath(path);
    // Remove trailing slash if present
    if (!fullPath.empty() && (fullPath.back() == '\\' || fullPath.back() == '/'))
        fullPath.pop_back();

    // Find the last backslash (before the exe name)
    size_t lastSlash = fullPath.find_last_of("\\/");
    if (lastSlash == string::npos) return {};

    // Remove the exe name
    auto dirPath = fullPath.substr(0, lastSlash);

    // Find the last folder
    size_t folderSlash = dirPath.find_last_of("\\/");
    if (folderSlash == string::npos)
        return dirPath;

    return dirPath.substr(folderSlash + 1);
}

bool listProcessEvents(DWORD pid)
{
    ULONG bufferSize = 0;
    ULONG needed = 0;

    bool ret = false;

    constexpr LONG SystemFullProcessInformation = 0x94;

    unique_ptr<char[]> bufferPtr;
    NTSTATUS status;

    for (int attempts = 0; attempts < 3; attempts++) {
        bufferPtr.reset(new char[bufferSize]);
        status = NtQuerySystemInformation(SystemHandleInformation, bufferPtr.get(), bufferSize, &needed);

        if (NT_SUCCESS(status)) {
            break;
        }
        else if (status == 0xC0000004) { // STATUS_INFO_LENGTH_MISMATCH
            bufferSize = needed + (needed / 10); // Add 10% extra
        }
        else {
            cerr << "NtQuerySystemInformation failed: 0x" << hex << status << endl;
            return ret;
        }
    }


    status = NtQuerySystemInformation(SystemHandleInformation, bufferPtr.get(), bufferSize, &needed);

    if (!NT_SUCCESS(status)) {
        cerr << "NtQuerySystemInformation failed: 0x" << hex << status << endl;
        return ret;
    }

    auto* info = reinterpret_cast<SYSTEM_HANDLE_INFORMATION*>(bufferPtr.get());
    HANDLE processHandle = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);
    if (!processHandle) {
        cerr << "Failed to open process " << pid << endl;
        return ret;
    }

    char typeInfo[1024];
    char nameInfo[1024];

    const char marker[] = { "DiabloII Check For Other Instances" };

    for (ULONG i = 0; i < info->HandleCount; ++i) {
        const auto& h = info->Handles[i];
        if (h.ProcessId != pid) continue;

        HANDLE dupHandle = NULL;
        if (!DuplicateHandle(processHandle, (HANDLE)(ULONG_PTR)h.Handle,
            GetCurrentProcess(), &dupHandle, 0, FALSE, DUPLICATE_SAME_ACCESS))
            continue;

        if (NtQueryObject(dupHandle, ObjectTypeInformation, typeInfo, (ULONG)sizeof(typeInfo), nullptr) == 0) {
            auto* typeName = (UNICODE_STRING*)typeInfo;
            if (typeName->Buffer && wcsstr(typeName->Buffer, L"Event")) {
                if (NtQueryObject(dupHandle, ObjectNameInformation, nameInfo, (ULONG)sizeof(nameInfo), nullptr) == 0) {
                    auto* name = (UNICODE_STRING*)(nameInfo);
                    if (name->Buffer && name->Length > 0) {
                        wstring ws(name->Buffer, name->Length / sizeof(WCHAR));
                        string narrow(ws.begin(), ws.end());
                        if (narrow.size() > sizeof(marker) && !memcmp(narrow.data() + narrow.size() - sizeof(marker) + 1, marker, sizeof(marker) - 1)) {
                            
                            cout << "   *** Processed [" << getLastFolderName(pid) << "]\n";

                            HANDLE hTarget;
                            ::DuplicateHandle(processHandle, (HANDLE)(ULONG_PTR)h.Handle, ::GetCurrentProcess(), &hTarget,
                                0, FALSE, DUPLICATE_CLOSE_SOURCE);
                            ::CloseHandle(hTarget);
                            ret = true;
                        }
                    }
                }
            }
        }
        CloseHandle(dupHandle);
    }

    CloseHandle(processHandle);

    return ret;
}

DWORD findProcessId(const string& exeName)
{
    PROCESSENTRY32 entry{};
    entry.dwSize = sizeof(entry);
    DWORD pid = 0;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    if (Process32First(snapshot, &entry)) {
        do {
            if (_stricmp(entry.szExeFile, exeName.c_str()) == 0) {
                pid = entry.th32ProcessID;
                listProcessEvents(pid);
            }
        } while (Process32Next(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return pid;
}

bool EnableAdminPrivileges()
{
    HANDLE token;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return false;
    if (!LookupPrivilegeValueA(nullptr, SE_DEBUG_NAME, &luid))
        return false;

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    CloseHandle(token);
    return GetLastError() == ERROR_SUCCESS;
}

int main(int argc, char** argv) {

    EnableAdminPrivileges();

    cout << "Monitoring for d2r.exe...\n";
    DWORD lastPid = 0;

    while (true) {
        auto pid = findProcessId("d2r.exe");
        if (pid != 0 && pid != lastPid) {
            auto changeMade = listProcessEvents(pid);
            lastPid = pid;
            if (changeMade) {
                Sleep(200);
                continue;
            }
        }
        Sleep(5000);
    }
}
