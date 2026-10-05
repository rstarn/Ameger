#include <Windows.h>
#include <TlHelp32.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <conio.h>
#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <fcntl.h>
#include <io.h>
#include <climits>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <fstream>
#include <sstream>
#include <iostream>
#include <limits>
#include <string>
#include <vector>
#include <memory>
#include <utility>

#include "../../Ameger/Injection.h"
#include "../../Ameger/Core/Foundation/Error.h"
#include "../../Ameger/Core/Foundation/Primitives/KcStrings/Core/XorString.h"
#include "../../Ameger/Core/Utility/PE/PEImage.h"
#include "../../Ameger/NT/NTDefinitions.h"

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")

#ifndef AMEGER_RUNTIME_DLL_HASH0
#define AMEGER_RUNTIME_DLL_HASH0 0
#endif
#ifndef AMEGER_RUNTIME_DLL_HASH1
#define AMEGER_RUNTIME_DLL_HASH1 0
#endif
#ifndef AMEGER_RUNTIME_DLL_HASH2
#define AMEGER_RUNTIME_DLL_HASH2 0
#endif
#ifndef AMEGER_RUNTIME_DLL_HASH3
#define AMEGER_RUNTIME_DLL_HASH3 0
#endif
#ifndef AMEGER_RUNTIME_DLL_HASH4
#define AMEGER_RUNTIME_DLL_HASH4 0
#endif
#ifndef AMEGER_RUNTIME_DLL_HASH5
#define AMEGER_RUNTIME_DLL_HASH5 0
#endif
#ifndef AMEGER_RUNTIME_DLL_HASH6
#define AMEGER_RUNTIME_DLL_HASH6 0
#endif
#ifndef AMEGER_RUNTIME_DLL_HASH7
#define AMEGER_RUNTIME_DLL_HASH7 0
#endif

#ifndef RECA_DEFINED
#define RECA_DEFINED
#define ReCa reinterpret_cast
#endif

namespace
{
    // Runtime state and Interface helpers.
    constexpr wchar_t kReset[] = L"\x1b[0m";
    constexpr wchar_t kGreen[] = L"\x1b[92m";
    constexpr wchar_t kRed[] = L"\x1b[91m";
    constexpr wchar_t kYellow[] = L"\x1b[93m";
    // Muted, for field labels and alignment scaffolding that should recede
    // behind the result values.
    constexpr wchar_t kDim[] = L"\x1b[2m";

    // Redirects runtime output while the DLL is being loaded.
    class StdoutParkGuard
    {
        int saved_stdout_fd_ = -1;
        int saved_stderr_fd_ = -1;
        HANDLE saved_stdout_handle_ = nullptr;
        HANDLE saved_stderr_handle_ = nullptr;
        HANDLE stdout_nul_ = INVALID_HANDLE_VALUE;
        HANDLE stderr_nul_ = INVALID_HANDLE_VALUE;

    public:
        StdoutParkGuard()
        {
            fflush(stdout);
            fflush(stderr);

            saved_stdout_fd_ = _dup(_fileno(stdout));
            saved_stderr_fd_ = _dup(_fileno(stderr));

            HANDLE nul = CreateFileW(L"NUL", GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
            int nul_fd = -1;
            if (nul != INVALID_HANDLE_VALUE)
            {
                nul_fd = _open_osfhandle(reinterpret_cast<intptr_t>(nul), _O_WRONLY);
                if (nul_fd == -1)
                {
                    CloseHandle(nul);
                }
            }
            if (saved_stdout_fd_ != -1 && nul_fd != -1)
            {
                (void)_dup2(nul_fd, _fileno(stdout));
            }
            if (nul_fd != -1)
            {
                _close(nul_fd);
            }

            nul = CreateFileW(L"NUL", GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
            nul_fd = -1;
            if (nul != INVALID_HANDLE_VALUE)
            {
                nul_fd = _open_osfhandle(reinterpret_cast<intptr_t>(nul), _O_WRONLY);
                if (nul_fd == -1)
                {
                    CloseHandle(nul);
                }
            }
            if (saved_stderr_fd_ != -1 && nul_fd != -1)
            {
                (void)_dup2(nul_fd, _fileno(stderr));
            }
            if (nul_fd != -1)
            {
                _close(nul_fd);
            }

            saved_stdout_handle_ = GetStdHandle(STD_OUTPUT_HANDLE);
            saved_stderr_handle_ = GetStdHandle(STD_ERROR_HANDLE);
            stdout_nul_ = CreateFileW(L"NUL", GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
            stderr_nul_ = CreateFileW(L"NUL", GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
            if (stdout_nul_ != INVALID_HANDLE_VALUE)
            {
                SetStdHandle(STD_OUTPUT_HANDLE, stdout_nul_);
            }
            if (stderr_nul_ != INVALID_HANDLE_VALUE)
            {
                SetStdHandle(STD_ERROR_HANDLE, stderr_nul_);
            }
        }

        ~StdoutParkGuard()
        {
            fflush(stdout);
            fflush(stderr);
            // A failed _dup2 leaves the stream pointed at NUL, so the restore
            // is best effort by nature and the return is deliberately
            // acknowledged rather than checked: there is no useful recovery
            // from a destructor, and the only consequence is that the original
            // stdout does not come back.
            if (saved_stdout_fd_ != -1)
            {
                (void)_dup2(saved_stdout_fd_, _fileno(stdout));
                _close(saved_stdout_fd_);
            }
            if (saved_stderr_fd_ != -1)
            {
                (void)_dup2(saved_stderr_fd_, _fileno(stderr));
                _close(saved_stderr_fd_);
            }
            if (stdout_nul_ != INVALID_HANDLE_VALUE)
            {
                SetStdHandle(STD_OUTPUT_HANDLE, saved_stdout_handle_);
                CloseHandle(stdout_nul_);
            }
            if (stderr_nul_ != INVALID_HANDLE_VALUE)
            {
                SetStdHandle(STD_ERROR_HANDLE, saved_stderr_handle_);
                CloseHandle(stderr_nul_);
            }
            clearerr(stdout);
            clearerr(stderr);
        }

        StdoutParkGuard(const StdoutParkGuard &) = delete;
        StdoutParkGuard & operator=(const StdoutParkGuard &) = delete;
    };

    class FileHandleGuard
    {
        HANDLE handle_ = INVALID_HANDLE_VALUE;

    public:
        FileHandleGuard() = default;

        explicit FileHandleGuard(HANDLE handle) : handle_(handle)
        {
        }

        ~FileHandleGuard()
        {
            reset();
        }

        FileHandleGuard(const FileHandleGuard &) = delete;
        FileHandleGuard & operator=(const FileHandleGuard &) = delete;

        FileHandleGuard(FileHandleGuard && other) noexcept : handle_(other.handle_)
        {
            other.handle_ = INVALID_HANDLE_VALUE;
        }

        FileHandleGuard & operator=(FileHandleGuard && other) noexcept
        {
            if (this != &other)
            {
                reset();
                handle_ = other.handle_;
                other.handle_ = INVALID_HANDLE_VALUE;
            }
            return *this;
        }

        void reset(HANDLE handle = INVALID_HANDLE_VALUE)
        {
            if (handle_ && handle_ != INVALID_HANDLE_VALUE)
            {
                CloseHandle(handle_);
            }
            handle_ = handle;
        }
    };

    // Process and file metadata used by the wizard.
    enum class Architecture
    {
        Unknown,
        X86,
        X64
    };

    struct MemoryInjectionData
    {
        BYTE * RawData;
        DWORD RawSize;
        DWORD ProcessID;
        INJECTION_MODE Mode;
        LAUNCH_METHOD Method;
        DWORD Flags;
        DWORD Timeout;
        ULONG_PTR hHandleValue;
        HINSTANCE hDllOut;
        bool GenerateErrorLog;
        DWORD TargetTid;
        ULONG_PTR hThreadHandleValue;
    };

    // Mirrors the runtime's MEMORY_INJECTIONDATA (Ameger/Injection.h). Assert the
    // size so a change on either side fails the build instead of silently
    // reinterpreting the other side's memory.
    static_assert(sizeof(MemoryInjectionData) == sizeof(MEMORY_INJECTIONDATA),
        "MemoryInjectionData must match the runtime's MEMORY_INJECTIONDATA layout");
    // Equal size alone would not catch a reordering that keeps the total the
    // same, so pin every field offset to its counterpart as well.
    static_assert(offsetof(MemoryInjectionData, RawData) == offsetof(MEMORY_INJECTIONDATA, RawData),
        "MemoryInjectionData::RawData offset must match MEMORY_INJECTIONDATA::RawData");
    static_assert(offsetof(MemoryInjectionData, RawSize) == offsetof(MEMORY_INJECTIONDATA, RawSize),
        "MemoryInjectionData::RawSize offset must match MEMORY_INJECTIONDATA::RawSize");
    static_assert(offsetof(MemoryInjectionData, ProcessID) == offsetof(MEMORY_INJECTIONDATA, ProcessID),
        "MemoryInjectionData::ProcessID offset must match MEMORY_INJECTIONDATA::ProcessID");
    static_assert(offsetof(MemoryInjectionData, Mode) == offsetof(MEMORY_INJECTIONDATA, Mode),
        "MemoryInjectionData::Mode offset must match MEMORY_INJECTIONDATA::Mode");
    static_assert(offsetof(MemoryInjectionData, Method) == offsetof(MEMORY_INJECTIONDATA, Method),
        "MemoryInjectionData::Method offset must match MEMORY_INJECTIONDATA::Method");
    static_assert(offsetof(MemoryInjectionData, Flags) == offsetof(MEMORY_INJECTIONDATA, Flags),
        "MemoryInjectionData::Flags offset must match MEMORY_INJECTIONDATA::Flags");
    static_assert(offsetof(MemoryInjectionData, Timeout) == offsetof(MEMORY_INJECTIONDATA, Timeout),
        "MemoryInjectionData::Timeout offset must match MEMORY_INJECTIONDATA::Timeout");
    static_assert(offsetof(MemoryInjectionData, hHandleValue) == offsetof(MEMORY_INJECTIONDATA, hHandleValue),
        "MemoryInjectionData::hHandleValue offset must match MEMORY_INJECTIONDATA::hHandleValue");
    static_assert(offsetof(MemoryInjectionData, hDllOut) == offsetof(MEMORY_INJECTIONDATA, hDllOut),
        "MemoryInjectionData::hDllOut offset must match MEMORY_INJECTIONDATA::hDllOut");
    static_assert(offsetof(MemoryInjectionData, GenerateErrorLog) == offsetof(MEMORY_INJECTIONDATA, GenerateErrorLog),
        "MemoryInjectionData::GenerateErrorLog offset must match MEMORY_INJECTIONDATA::GenerateErrorLog");
    static_assert(offsetof(MemoryInjectionData, TargetTid) == offsetof(MEMORY_INJECTIONDATA, TargetTid),
        "MemoryInjectionData::TargetTid offset must match MEMORY_INJECTIONDATA::TargetTid");
    static_assert(offsetof(MemoryInjectionData, hThreadHandleValue) == offsetof(MEMORY_INJECTIONDATA, hThreadHandleValue),
        "MemoryInjectionData::hThreadHandleValue offset must match MEMORY_INJECTIONDATA::hThreadHandleValue");

    using f_Memory_Inject = DWORD(__stdcall *)(MemoryInjectionData *);

    struct Runtime
    {
        HMODULE module = nullptr;
        f_Memory_Inject memory_inject = nullptr;
        f_GetSymbolState get_symbol_state = nullptr;
        f_GetImportState get_import_state = nullptr;
        f_InitializeRuntime initialize_runtime = nullptr;
        f_ShutdownRuntime shutdown_runtime = nullptr;
        f_StartDownload start_download = nullptr;
        f_SetRawPrintCallback set_raw_print_callback = nullptr;
        f_GetLastHijackStats get_last_hijack_stats = nullptr;
        f_GetLastMapStats get_last_map_stats = nullptr;
        f_GetLastStringStats get_last_string_stats = nullptr;
        f_GetLastThreadExecStats get_last_thread_exec_stats = nullptr;
    };

    bool ReadFileBytes(const std::wstring & path, std::vector<BYTE> & bytes);

    struct FileInformation
    {
        Architecture architecture = Architecture::Unknown;
        bool dotnet = false;
    };

    struct TargetSelection
    {
        DWORD pid = 0;
        std::wstring requested_name;
        std::wstring name;
        Architecture architecture = Architecture::Unknown;
        bool by_name = false;
        // Raw FILETIME creation stamp of the target, captured while
        // QueryProcess already held a query handle (no extra OpenProcess).
        // Used only to warn when injection lands late in the game's boot, the
        // suspected trigger for a payload DllMain that refuses to initialize.
        // 0 means "unknown".
        ULONGLONG creation_time = 0;
    };

    struct WizardConfig
    {
        int schema_version = 0;
        bool scramble = true;
        bool load_copy = true;
        bool handle_hijacking = true;
        bool hijack_scan = true;
        bool sponsor_roundtrip = true;
        bool verbose_trace = true;
        // Suppress the trace-heavy output (acquisition detail, hook scans) so a
        // captured stdout reveals as little as possible. The verdict still prints.
        bool quiet = false;
        bool hook_restore = true;
        bool run_dllmain = true;
        bool page_protections = true;
        bool loader_lock = true;
        bool exceptions = true;
        bool resolve_imports = true;
        bool security_cookie = true;
        bool delay_imports = true;
        bool clean_data = true;
        bool execute_tls = true;
        bool from_memory = true;
        int timeout = 60000;
        std::wstring target_name;
        std::wstring expected_payload_sha256;
    };

    // Console and process output helpers.
    void EnableAnsi()
    {
        HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD mode = 0;
        if (output != INVALID_HANDLE_VALUE && GetConsoleMode(output, &mode))
        {
            SetConsoleMode(output, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        }
    }

    void PrintError(const wchar_t * message)
    {
        fwprintf(stderr, L"%ls%ls%ls\n", kRed, message, kReset);
    }

    void PrintWarning(const wchar_t * message)
    {
        wprintf(L"%ls[!]%ls %ls\n", kYellow, kReset, message);
    }

    [[noreturn]] void TerminateInterface(int code)
    {
        fflush(stdout);
        fflush(stderr);
        TerminateProcess(GetCurrentProcess(), static_cast<UINT>(code));
        for (;;)
        {
            Sleep(1000);
        }
    }

    void __stdcall QuietPrint(const char *)
    {
    }

    std::wstring TrimText(const std::wstring & text)
    {
        const size_t first = text.find_first_not_of(L" \t\r\n");
        if (first == std::wstring::npos)
        {
            return std::wstring();
        }

        const size_t last = text.find_last_not_of(L" \t\r\n");
        std::wstring value = text.substr(first, last - first + 1);
        if (value.size() >= 2 && value.front() == L'"' && value.back() == L'"')
        {
            value = value.substr(1, value.size() - 2);
        }
        return value;
    }

    bool ReadLine(const wchar_t * prompt, std::wstring & value)
    {
        fflush(stdout);
        wprintf(L"%ls", prompt);
        if (!std::getline(std::wcin, value))
        {
            return false;
        }
        value = TrimText(value);
        return true;
    }

    bool ParseUnsigned(const std::wstring & text, unsigned long long & value)
    {
        if (text.empty() || text.front() == L'-')
        {
            return false;
        }

        wchar_t * end = nullptr;
        errno = 0;
        const unsigned long long parsed = std::wcstoull(text.c_str(), &end, 10);
        if (errno == ERANGE || end == text.c_str() || *end != L'\0')
        {
            return false;
        }

        value = parsed;
        return true;
    }

    bool ParseDword(const std::wstring & text, DWORD & value)
    {
        unsigned long long parsed = 0;
        if (!ParseUnsigned(text, parsed) || parsed > (std::numeric_limits<DWORD>::max)())
        {
            return false;
        }

        value = static_cast<DWORD>(parsed);
        return true;
    }

    bool ReadYesNo(const wchar_t * prompt, bool default_value, bool & value)
    {
        for (;;)
        {
            wprintf(L"%ls [%ls]: ", prompt, default_value ? L"Y" : L"N");
            std::wstring text;
            if (!ReadLine(L"", text))
            {
                return false;
            }
            if (text.empty())
            {
                value = default_value;
                return true;
            }
            if (text == L"y" || text == L"Y" || _wcsicmp(text.c_str(), L"yes") == 0)
            {
                value = true;
                return true;
            }
            if (text == L"n" || text == L"N" || _wcsicmp(text.c_str(), L"no") == 0)
            {
                value = false;
                return true;
            }
            PrintWarning(L"Answer y or n.");
        }
    }

    // Resolves paths relative to the Interface executable.
    std::wstring ExecutableDirectory()
    {
        std::vector<wchar_t> buffer(MAX_PATH * 2);
        const DWORD length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (!length || length >= buffer.size())
        {
            return std::wstring();
        }

        const std::wstring path(buffer.data(), length);
        const size_t slash = path.find_last_of(L"\\/");
        return slash == std::wstring::npos ? std::wstring() : path.substr(0, slash + 1);
    }

    // Runtime DLL file name is derived from the embedded SHA-256, matching the
    // name Create.bat deploys into Release\DLLs (rtdll_<first 8 hex>). No fixed
    // on-disk name is baked in, so a shipped folder exposes no stable file
    // fingerprint. A stock checkout leaves the hash at zero, so the name
    // resolves to a file that does not exist and the missing-DLL path refuses
    // to run.
    std::wstring RuntimeFileName()
    {
        constexpr wchar_t hex[] = L"0123456789ABCDEF";
        std::wstring name = L"rtdll_";
        for (int shift = 28; shift >= 0; shift -= 4)
        {
            name.push_back(hex[(AMEGER_RUNTIME_DLL_HASH0 >> shift) & 0x0F]);
        }
        name += L".dll";
        return name;
    }

    std::wstring RuntimePath()
    {
        const std::wstring directory = ExecutableDirectory();
        return directory.empty() ? std::wstring() : directory + L"DLLs\\" + RuntimeFileName();
    }

    bool FileExists(const std::wstring & path)
    {
        const DWORD attributes = GetFileAttributesW(path.c_str());
        return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
    }

    // Best-effort SeDebugPrivilege so the sponsor pre-open below (and any
    // donor-owner opens) can target SYSTEM processes. The runtime enables it
    // again in-process; doing it here first wins the race at detection time.
    // Returns true when the privilege is confirmed enabled.
    // Console output is a fingerprint. Anything printed here can end up in a
    // captured log, a scrollback buffer, or a screenshot, and the combination
    // of target name, payload path and payload digest identifies both the tool
    // and the exact build. The identifying detail is therefore suppressed by
    // default and restored only on request with AMEGER_VERBOSE=1. Declared here,
    // ahead of its first use, because it is called from both the banner and the
    // report stages.
    bool VerboseOutputEnabled()
    {
        static const bool verbose = []() -> bool
        {
            wchar_t buffer[8] = {};
            const DWORD got = GetEnvironmentVariableW(L"AMEGER_VERBOSE", buffer, 4);
            return (got == 1 && buffer[0] == L'1');
        }();
        return verbose;
    }

    bool EnableSeDebugPrivilege()
    {
        HANDLE token = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        {
            return false;
        }
        FileHandleGuard tokenGuard(token);

        LUID luid{};
        if (!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid))
        {
            return false;
        }

        TOKEN_PRIVILEGES privileges{};
        privileges.PrivilegeCount = 1;
        privileges.Privileges[0].Luid = luid;
        privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if (!AdjustTokenPrivileges(token, FALSE, &privileges, sizeof(privileges), nullptr, nullptr))
        {
            return false;
        }

        // Status is computed inside the marked region: the end marker must be
        // the last statement before the return, matching every other annotated
        // function, so the whole body is protected.
        const DWORD status = GetLastError();
        return status == ERROR_SUCCESS;
    }

    // Counterpart to EnableSeDebugPrivilege. An enabled SeDebugPrivilege is
    // durable token state that survives on this process for its whole lifetime
    // and is visible to anything that inspects our token, so the privilege is
    // dropped again as soon as the fallback open has been attempted. Dropping
    // it cannot invalidate handles already obtained.
    void DisableSeDebugPrivilege()
    {
        HANDLE token = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        {
            return;
        }
        FileHandleGuard tokenGuard(token);

        LUID luid{};
        if (!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid))
        {
            return;
        }

        TOKEN_PRIVILEGES privileges{};
        privileges.PrivilegeCount = 1;
        privileges.Privileges[0].Luid = luid;
        // SE_PRIVILEGE_REMOVED, not just clearing SE_PRIVILEGE_ENABLED, so the
        // privilege leaves the token rather than lingering disabled-but-held.
        privileges.Privileges[0].Attributes = SE_PRIVILEGE_REMOVED;
        AdjustTokenPrivileges(token, FALSE, &privileges, sizeof(privileges), nullptr, nullptr);
    }

    // Minimal SystemProcessInformation view: only the fields the victim
    // picker needs. Kept local rather than reusing the runtime's
    // SYSTEM_PROCESS_INFORMATION / SYSTEM_THREAD_INFORMATION directly, but
    // bound to them at compile time by the asserts below (NTDefinitions.h is
    // included above for exactly that), so the two copies cannot silently
    // diverge.
    struct SpiUnicodeStringLocal
    {
        USHORT Length;
        USHORT MaximumLength;
        wchar_t * Buffer;
    };

    struct SpiClientIdLocal
    {
        HANDLE UniqueProcess;
        HANDLE UniqueThread;
    };

    struct SpiThreadLocal
    {
        LARGE_INTEGER KernelTime;
        LARGE_INTEGER UserTime;
        LARGE_INTEGER CreateTime;
        ULONG WaitTime;
        PVOID StartAddress;
        SpiClientIdLocal ClientId;
        LONG Priority;
        LONG BasePriority;
        ULONG ContextSwitches;
        unsigned char ThreadState;
        unsigned char WaitReason;
    };

    struct SpiProcessLocal
    {
        ULONG NextEntryOffset;
        ULONG NumberOfThreads;
        LARGE_INTEGER WorkingSetPrivateSize;
        ULONG HardFaultCount;
        ULONG NumberOfThreadsHighWatermark;
        ULONGLONG CycleTime;
        LARGE_INTEGER CreateTime;
        LARGE_INTEGER UserTime;
        LARGE_INTEGER KernelTime;
        SpiUnicodeStringLocal ImageName;
        LONG BasePriority;
        HANDLE UniqueProcessId;
        HANDLE InheritedFromUniqueProcessId;
        ULONG HandleCount;
        ULONG SessionId;
        ULONG_PTR UniqueProcessKey;
        SIZE_T PeakVirtualSize;
        SIZE_T VirtualSize;
        ULONG PageFaultCount;
        SIZE_T PeakWorkingSetSize;
        SIZE_T WorkingSetSize;
        SIZE_T QuotaPeakPagedPoolUsage;
        SIZE_T QuotaPagedPoolUsage;
        SIZE_T QuotaPeakNonPagedPoolUsage;
        SIZE_T QuotaNonPagedPoolUsage;
        SIZE_T PagefileUsage;
        SIZE_T PeakPagefileUsage;
        SIZE_T PrivatePageCount;
        LARGE_INTEGER ReadOperationCount;
        LARGE_INTEGER WriteOperationCount;
        LARGE_INTEGER OtherOperationCount;
        LARGE_INTEGER ReadTransferCount;
        LARGE_INTEGER WriteTransferCount;
        LARGE_INTEGER OtherTransferCount;
        SpiThreadLocal Threads[1];
    };

    static_assert(sizeof(SpiUnicodeStringLocal) == 16);
    static_assert(sizeof(SpiClientIdLocal) == 16);
    static_assert(offsetof(SpiThreadLocal, ThreadState) == 68);
    static_assert(sizeof(SpiThreadLocal) == 72);
    static_assert(offsetof(SpiProcessLocal, UniqueProcessId) == 0x50);
    static_assert(offsetof(SpiProcessLocal, Threads) == 0x100);

    // Compile-time equivalence proof against the runtime's own definitions
    // (Ameger/NT/NTDefinitions.h). Binding every field the host walks - not
    // just the raw offsets above - means a change to either copy fails the
    // build here instead of silently reinterpreting the other side's memory.
    static_assert(offsetof(SpiThreadLocal, ThreadState) == offsetof(SYSTEM_THREAD_INFORMATION, ThreadState),
        "SpiThreadLocal::ThreadState must mirror SYSTEM_THREAD_INFORMATION::ThreadState");
    static_assert(offsetof(SpiThreadLocal, WaitReason) == offsetof(SYSTEM_THREAD_INFORMATION, WaitReason),
        "SpiThreadLocal::WaitReason must mirror SYSTEM_THREAD_INFORMATION::WaitReason");
    static_assert(offsetof(SpiThreadLocal, ClientId) == offsetof(SYSTEM_THREAD_INFORMATION, ClientId),
        "SpiThreadLocal::ClientId must mirror SYSTEM_THREAD_INFORMATION::ClientId");
    static_assert(offsetof(SpiThreadLocal, Priority) == offsetof(SYSTEM_THREAD_INFORMATION, Priority),
        "SpiThreadLocal::Priority must mirror SYSTEM_THREAD_INFORMATION::Priority");
    static_assert(offsetof(SpiThreadLocal, BasePriority) == offsetof(SYSTEM_THREAD_INFORMATION, BasePriority),
        "SpiThreadLocal::BasePriority must mirror SYSTEM_THREAD_INFORMATION::BasePriority");
    static_assert(sizeof(SpiThreadLocal) == sizeof(SYSTEM_THREAD_INFORMATION),
        "SpiThreadLocal must match the runtime's SYSTEM_THREAD_INFORMATION size");

    static_assert(offsetof(SpiProcessLocal, NextEntryOffset) == offsetof(SYSTEM_PROCESS_INFORMATION, NextEntryOffset),
        "SpiProcessLocal::NextEntryOffset must mirror SYSTEM_PROCESS_INFORMATION::NextEntryOffset");
    static_assert(offsetof(SpiProcessLocal, NumberOfThreads) == offsetof(SYSTEM_PROCESS_INFORMATION, NumberOfThreads),
        "SpiProcessLocal::NumberOfThreads must mirror SYSTEM_PROCESS_INFORMATION::NumberOfThreads");
    static_assert(offsetof(SpiProcessLocal, UniqueProcessId) == offsetof(SYSTEM_PROCESS_INFORMATION, UniqueProcessId),
        "SpiProcessLocal::UniqueProcessId must mirror SYSTEM_PROCESS_INFORMATION::UniqueProcessId");
    static_assert(offsetof(SpiProcessLocal, Threads) == offsetof(SYSTEM_PROCESS_INFORMATION, Threads),
        "SpiProcessLocal::Threads must mirror SYSTEM_PROCESS_INFORMATION::Threads");
    static_assert(sizeof(SpiProcessLocal) == sizeof(SYSTEM_PROCESS_INFORMATION),
        "SpiProcessLocal must match the runtime's SYSTEM_PROCESS_INFORMATION size");

    // Picks a hijack-victim thread for the target with a pure
    // SystemProcessInformation query (nothing is opened, nothing is touched
    // in the target). Returns 0 when no suitable thread exists - the runtime
    // then falls back to its own search. Scoring: a parked Waiting thread
    // (except WrQueue) beats Running beats anything else. A Running thread
    // is liable to be inside a scan/dispatch loop, where suspending it skews
    // timing checks and parks anomalous state; a waiter sits in ntdll with a
    // clean stack, so borrowing it for the 1-3 s shell run is lower-signal.
    DWORD PickHijackThreadTid(DWORD target_pid)
    {
        if (!target_pid)
        {
            return 0;
        }

        using NtQuerySystemInformationFn = LONG(NTAPI *)(ULONG, PVOID, ULONG, PULONG);
        NtQuerySystemInformationFn NtQuery = nullptr;
        {
            auto mod_name = XOR_STR_W(L"ntdll.dll");
            HMODULE mod = GetModuleHandleW(mod_name.get());
            // ntdll is always loaded, so a null handle here means something is
            // badly wrong. Check it rather than passing it to GetProcAddress:
            // a null module argument is not a supported input, and the result
            // is only null "by accident".
            if (mod)
            {
                auto api_name = XOR_STR_A("NtQuerySystemInformation");
                NtQuery = ReCa<NtQuerySystemInformationFn>(
                    GetProcAddress(mod, api_name.get()));
            }
        }
        if (!NtQuery)
        {
            return 0;
        }

        std::vector<BYTE> buffer(1 << 20);
        ULONG size = static_cast<ULONG>(buffer.size());
        LONG status = NtQuery(5, buffer.data(), size, &size);
        while (static_cast<DWORD>(status) == 0xC0000004u)
        {
            ULONG grow = size > buffer.size() ? size : static_cast<ULONG>(buffer.size() * 2);
            if (grow > (16u << 20))
            {
                return 0;
            }

            buffer.resize(grow);
            size = grow;
            status = NtQuery(5, buffer.data(), size, &size);
        }

        if (status != 0)
        {
            return 0;
        }

        DWORD best_tid = 0;
        int best_score = 0;
        size_t offset = 0;
        for (;;)
        {
            if (offset + offsetof(SpiProcessLocal, Threads) > buffer.size())
            {
                break;
            }

            const auto * proc = ReCa<const SpiProcessLocal *>(buffer.data() + offset);
            if (static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(proc->UniqueProcessId)) == target_pid)
            {
                const size_t threads_base = offset + offsetof(SpiProcessLocal, Threads);
                for (ULONG index = 0; index < proc->NumberOfThreads; ++index)
                {
                    const size_t entry = threads_base + static_cast<size_t>(index) * sizeof(SpiThreadLocal);
                    if (entry + sizeof(SpiThreadLocal) > buffer.size())
                    {
                        break;
                    }

                    const auto * thread = ReCa<const SpiThreadLocal *>(buffer.data() + entry);
                    const DWORD tid = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(thread->ClientId.UniqueThread));
                    if (!tid || tid == GetCurrentThreadId())
                    {
                        continue;
                    }

                    int score = 1;
                    if (thread->ThreadState == 5 && thread->WaitReason != 0x0F) // Waiting, not WrQueue
                    {
                        score = 3;
                    }
                    else if (thread->ThreadState == 2) // Running
                    {
                        score = 2;
                    }

                    // Deterministic main-thread bias: snapshot order is not
                    // guaranteed, so ties break toward the smallest TID. The
                    // main thread is created first (lowest TID) and is the
                    // most likely to be in a stable alertable wait early in
                    // boot; without this, late-boot thread-pool/Warden threads
                    // win the lottery depending on enumeration order and the
                    // payload's DllMain runs on a different thread each run.
                    if (score > best_score ||
                        (score == best_score && best_tid != 0 && tid < best_tid))
                    {
                        best_score = score;
                        best_tid = tid;
                    }
                }

                break;
            }

            if (!proc->NextEntryOffset || proc->NextEntryOffset < 8)
            {
                break;
            }

            offset += proc->NextEntryOffset;
        }

        return best_tid;
    }

    // Interface-side half of the acquisition trace: facts only the injector
    // process knows (config, privilege, pre-open). The runtime half arrives
    // via HijackStats. Both print in the first step of the dynamic acquisition
    // trace (the step total varies with the path taken; see PrintHijackTrace).
    struct HijackContext
    {
        bool PrivilegeAttempted = false;
        bool PrivilegeOk = false;
        bool SponsorOpened = false;
        ULONG_PTR SponsorValue = 0;
        DWORD SponsorAccess = 0;
        DWORD TargetPid = 0;
        std::wstring TargetName;
        bool SponsorThreadAttempted = false;
        bool SponsorThreadOpened = false;
        ULONG_PTR SponsorThreadValue = 0;
        DWORD SponsorTid = 0;
        // The TID the runtime actually hijacked, reported by the thread-exec
        // telemetry. Populated before the acquisition trace is printed so the
        // trace can name a sponsor-vs-used mismatch explicitly instead of
        // leaving the reader to cross-reference two distant lines.
        DWORD UsedTid = 0;
        bool Verbose = true;
    };

    std::wstring CanonicalPath(const std::wstring & path)
    {
        std::vector<wchar_t> buffer(MAX_PATH * 4);
        const DWORD length = GetFullPathNameW(path.c_str(), static_cast<DWORD>(buffer.size()), buffer.data(), nullptr);
        if (!length || length >= buffer.size())
        {
            return std::wstring();
        }
        return std::wstring(buffer.data(), length);
    }

    bool EqualsNoCase(const std::wstring & value, const wchar_t * expected)
    {
        return _wcsicmp(value.c_str(), expected) == 0;
    }

    std::wstring ConfigurationPath()
    {
        const std::wstring directory = ExecutableDirectory();
        if (directory.empty())
        {
            return std::wstring();
        }

        // Order matters: the deployed (DPAPI-encrypted) copy next to the EXE is
        // preferred over the plaintext master in Build\, so a shipped folder
        // exposes no readable configuration. The plaintext path remains as the
        // development fallback.
        const wchar_t * candidates[] =
        {
            L"Configuration.ini",
            L"..\\Configuration.ini",
            L"..\\..\\Build\\Configuration.ini"
        };
        for (const wchar_t * candidate : candidates)
        {
            const std::wstring path = CanonicalPath(directory + candidate);
            if (!path.empty() && FileExists(path))
            {
                return path;
            }
        }
        return std::wstring();
    }

    bool ParseConfigBool(const std::wstring & value, bool default_value)
    {
        if (EqualsNoCase(value, L"y") || EqualsNoCase(value, L"yes") || EqualsNoCase(value, L"1") || EqualsNoCase(value, L"true"))
        {
            return true;
        }
        if (EqualsNoCase(value, L"n") || EqualsNoCase(value, L"no") || EqualsNoCase(value, L"0") || EqualsNoCase(value, L"false"))
        {
            return false;
        }
        return default_value;
    }

    // Encrypted-config marker. A DPAPI blob has no intrinsic signature, so the
    // file carries this 8-byte prefix; a config without it is refused outright,
    // because there is deliberately no plaintext fallback.
    constexpr char kConfigBlobMagic[8] = { 'S', 'Y', 'S', 'C', 'F', 'G', '0', '1' };

    // Decrypts a DPAPI-protected config produced by Build\Scripts\ProtectConfig.ps1.
    // Scope is CurrentUser, matching the writer, so the file is readable only by
    // the account that encrypted it. Returns false for plaintext input.
    bool DecryptConfigBlob(const std::string & raw, std::string & out)
    {
        out.clear();

        if (raw.size() <= sizeof(kConfigBlobMagic) ||
            memcmp(raw.data(), kConfigBlobMagic, sizeof(kConfigBlobMagic)) != 0)
        {
            return false;
        }

        DATA_BLOB input{};
        input.cbData = static_cast<DWORD>(raw.size() - sizeof(kConfigBlobMagic));
        input.pbData = reinterpret_cast<BYTE *>(const_cast<char *>(raw.data() + sizeof(kConfigBlobMagic)));

        DATA_BLOB output{};
        if (!CryptUnprotectData(&input, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &output))
        {
            return false;
        }

        out.assign(reinterpret_cast<const char *>(output.pbData), output.cbData);
        LocalFree(output.pbData);
        return true;
    }

    // Loads defaults and overrides from Build\\Configuration.ini.
    bool LoadWizardConfig(WizardConfig & config, std::wstring & path, bool & invalid)
    {
        config = WizardConfig{};
        invalid = false;
        path = ConfigurationPath();
        if (path.empty())
        {
            return false;
        }

        std::string raw_bytes;
        {
            std::ifstream raw_file(path, std::ios::binary | std::ios::ate);
            if (!raw_file.good())
            {
                invalid = true;
                return false;
            }

            const std::streamoff raw_size = raw_file.tellg();
            if (raw_size < 0 || static_cast<unsigned long long>(raw_size) > 1024 * 1024)
            {
                invalid = true;
                return false;
            }

            raw_bytes.resize(static_cast<size_t>(raw_size));
            raw_file.seekg(0, std::ios::beg);
            raw_file.read(raw_bytes.data(), raw_size);
            if (!raw_file || raw_file.gcount() != raw_size)
            {
                invalid = true;
                return false;
            }
        }

        std::wstring config_text;
        std::string plaintext;
        if (DecryptConfigBlob(raw_bytes, plaintext))
        {
            raw_bytes.swap(plaintext);
        }
        else
        {
            // No plaintext fallback: a config that is not a DPAPI blob carrying
            // the expected magic is refused outright. Accepting plaintext here
            // would let a shipped plaintext ini be parsed, which is exactly the
            // self-describing on-disk artifact the encryption exists to prevent.
            // A magic-bearing blob that DPAPI refuses (wrong account or host)
            // also lands here rather than being mis-parsed as an ini.
            invalid = true;
            return false;
        }
        if (!raw_bytes.empty())
        {
            const int required = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, raw_bytes.c_str(), static_cast<int>(raw_bytes.size()), nullptr, 0);
            if (required <= 0)
            {
                invalid = true;
                return false;
            }

            config_text.resize(static_cast<size_t>(required), L'\0');
            if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, raw_bytes.c_str(), static_cast<int>(raw_bytes.size()), config_text.data(), required))
            {
                invalid = true;
                return false;
            }

            if (!config_text.empty() && config_text.front() == 0xFEFF)
            {
                config_text.erase(config_text.begin());
            }
        }

        std::wstringstream file(config_text);

        std::wstring section;
        std::wstring line;
        while (std::getline(file, line))
        {
            if (!line.empty() && line.back() == L'\r')
            {
                line.pop_back();
            }

            const std::wstring text = TrimText(line);
            if (text.empty() || text.front() == L';' || text.front() == L'#')
            {
                continue;
            }
            if (text.size() >= 2 && text.front() == L'[' && text.back() == L']')
            {
                section = text.substr(1, text.size() - 2);
                continue;
            }

            const size_t separator = text.find(L'=');
            if (separator == std::wstring::npos)
            {
                continue;
            }

            const std::wstring key = TrimText(text.substr(0, separator));
            std::wstring value = TrimText(text.substr(separator + 1));
            bool quoted = false;
            size_t comment = std::wstring::npos;
            for (size_t i = 0; i < value.size(); ++i)
            {
                if (value[i] == L'"')
                {
                    quoted = !quoted;
                }
                else if (!quoted && (value[i] == L';' || value[i] == L'#'))
                {
                    comment = i;
                    break;
                }
            }
            if (comment != std::wstring::npos)
            {
                value = TrimText(value.substr(0, comment));
            }
            if (value.size() >= 2 && value.front() == L'"' && value.back() == L'"')
            {
                value = value.substr(1, value.size() - 2);
            }

            const bool general = EqualsNoCase(section, L"General");
            const bool manual = EqualsNoCase(section, L"ManualMap");
            if (general && EqualsNoCase(key, L"SchemaVersion"))
            {
                DWORD parsed = 0;
                if (ParseDword(value, parsed) && parsed <= static_cast<DWORD>(INT_MAX))
                {
                    config.schema_version = static_cast<int>(parsed);
                }
            }
            else if (general && EqualsNoCase(key, L"ProcessName"))
            {
                config.target_name = value;
            }
            else if (general && EqualsNoCase(key, L"PayloadSha256"))
            {
                config.expected_payload_sha256 = value;
                std::transform(config.expected_payload_sha256.begin(), config.expected_payload_sha256.end(), config.expected_payload_sha256.begin(), towupper);
            }
            else if (general && EqualsNoCase(key, L"LoadCopy"))
            {
                config.load_copy = ParseConfigBool(value, config.load_copy);
            }
            else if (general && EqualsNoCase(key, L"ScrambleDllName"))
            {
                config.scramble = ParseConfigBool(value, config.scramble);
            }
            else if (general && EqualsNoCase(key, L"HandleHijacking"))
            {
                config.handle_hijacking = ParseConfigBool(value, config.handle_hijacking);
            }
            else if (general && EqualsNoCase(key, L"HijackScan"))
            {
                config.hijack_scan = ParseConfigBool(value, config.hijack_scan);
            }
            else if (general && EqualsNoCase(key, L"SponsorRoundtrip"))
            {
                config.sponsor_roundtrip = ParseConfigBool(value, config.sponsor_roundtrip);
            }
            else if (general && EqualsNoCase(key, L"VerboseTrace"))
            {
                config.verbose_trace = ParseConfigBool(value, config.verbose_trace);
            }
            else if (general && EqualsNoCase(key, L"Quiet"))
            {
                config.quiet = ParseConfigBool(value, config.quiet);
            }
            else if (general && EqualsNoCase(key, L"HookRestore"))
            {
                config.hook_restore = ParseConfigBool(value, config.hook_restore);
            }
            else if (general && EqualsNoCase(key, L"Timeout"))
            {
                DWORD parsed = 0;
                // Clamp to INT_MAX: a value >= 0x80000000 would narrow to a
                // negative int and later widen to a huge DWORD timeout.
                if (ParseDword(value, parsed) && parsed >= 1000 && parsed <= static_cast<DWORD>(INT_MAX))
                {
                    config.timeout = static_cast<int>(parsed);
                }
            }
            else if (manual && EqualsNoCase(key, L"ExecuteTLS"))
            {
                config.execute_tls = ParseConfigBool(value, config.execute_tls);
            }
            else if (manual && EqualsNoCase(key, L"RunDLLMain"))
            {
                config.run_dllmain = ParseConfigBool(value, config.run_dllmain);
            }
            else if (manual && EqualsNoCase(key, L"LoadFromMemory"))
            {
                config.from_memory = ParseConfigBool(value, config.from_memory);
            }
            else if (manual && EqualsNoCase(key, L"LockLoaderLock"))
            {
                config.loader_lock = ParseConfigBool(value, config.loader_lock);
            }
            else if (manual && EqualsNoCase(key, L"ResolveImports"))
            {
                config.resolve_imports = ParseConfigBool(value, config.resolve_imports);
            }
            else if (manual && EqualsNoCase(key, L"EnableExceptions"))
            {
                config.exceptions = ParseConfigBool(value, config.exceptions);
            }
            else if (manual && EqualsNoCase(key, L"InitSecurityCookie"))
            {
                config.security_cookie = ParseConfigBool(value, config.security_cookie);
            }
            else if (manual && EqualsNoCase(key, L"SetPageProtections"))
            {
                config.page_protections = ParseConfigBool(value, config.page_protections);
            }
            else if (manual && EqualsNoCase(key, L"ResolveDelayImports"))
            {
                config.delay_imports = ParseConfigBool(value, config.delay_imports);
            }
            else if (manual && EqualsNoCase(key, L"CleanDataDirectories"))
            {
                config.clean_data = ParseConfigBool(value, config.clean_data);
            }
        }

        if (config.schema_version != 1)
        {
            config = WizardConfig{};
            invalid = true;
            return false;
        }

        if (!config.expected_payload_sha256.empty())
        {
            bool valid_hash = config.expected_payload_sha256.size() == 64;
            for (wchar_t value : config.expected_payload_sha256)
            {
                valid_hash = valid_hash && ((value >= L'0' && value <= L'9') || (value >= L'A' && value <= L'F'));
            }
            if (!valid_hash)
            {
                config = WizardConfig{};
                invalid = true;
                return false;
            }
        }

        if (config.target_name.empty())
        {
            config = WizardConfig{};
            invalid = true;
            return false;
        }
        return true;
    }

    std::wstring Sha256Hex(const std::vector<BYTE> & bytes)
    {
        BCRYPT_ALG_HANDLE algorithm = nullptr;
        BCRYPT_HASH_HANDLE hash = nullptr;
        DWORD object_length = 0;
        DWORD result_length = 0;
        DWORD hash_length = 0;
        std::vector<BYTE> hash_object;
        std::vector<BYTE> hash_bytes;

        if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0 ||
            BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&object_length), sizeof(object_length), &result_length, 0) < 0 ||
            BCryptGetProperty(algorithm, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hash_length), sizeof(hash_length), &result_length, 0) < 0)
        {
            if (algorithm)
            {
                BCryptCloseAlgorithmProvider(algorithm, 0);
            }
            return std::wstring();
        }

        try
        {
            hash_object.resize(object_length);
            hash_bytes.resize(hash_length);
        }
        catch (const std::bad_alloc &)
        {
            BCryptCloseAlgorithmProvider(algorithm, 0);
            return std::wstring();
        }

        if (BCryptCreateHash(algorithm, &hash, hash_object.data(), object_length, nullptr, 0, BCRYPT_HASH_REUSABLE_FLAG) < 0)
        {
            BCryptCloseAlgorithmProvider(algorithm, 0);
            return std::wstring();
        }

        size_t offset = 0;
        while (offset < bytes.size())
        {
            const ULONG chunk = static_cast<ULONG>((std::min)(bytes.size() - offset, static_cast<size_t>(ULONG_MAX)));
            if (BCryptHashData(hash, const_cast<BYTE *>(bytes.data() + offset), chunk, 0) < 0)
            {
                BCryptDestroyHash(hash);
                BCryptCloseAlgorithmProvider(algorithm, 0);
                return std::wstring();
            }
            offset += chunk;
        }

        const NTSTATUS finish_status = BCryptFinishHash(hash, hash_bytes.data(), hash_length, 0);
        BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(algorithm, 0);
        if (finish_status < 0)
        {
            return std::wstring();
        }

        constexpr wchar_t hex[] = L"0123456789ABCDEF";
        std::wstring result;
        result.reserve(hash_bytes.size() * 2);
        for (BYTE value : hash_bytes)
        {
            result.push_back(hex[value >> 4]);
            result.push_back(hex[value & 0x0F]);
        }
        return result;
    }

    bool ReadHandleBytes(HANDLE file, std::vector<BYTE> & bytes)
    {
        LARGE_INTEGER size{};
        if (!GetFileSizeEx(file, &size))
        {
            fwprintf(stderr, L"%lsFailed to query runtime size: 0x%08X%ls\n", kRed, GetLastError(), kReset);
            return false;
        }
        if (size.QuadPart <= 0 || static_cast<unsigned long long>(size.QuadPart) > PE_IMAGE::MAX_IMAGE_SIZE)
        {
            fwprintf(stderr, L"%lsInvalid runtime size: %lld bytes%ls\n", kRed, size.QuadPart, kReset);
            return false;
        }

        bytes.resize(static_cast<size_t>(size.QuadPart));
        size_t total = 0;
        while (total < bytes.size())
        {
            DWORD read = 0;
            const size_t remaining = bytes.size() - total;
            const BOOL read_ok = ReadFile(file, bytes.data() + total, static_cast<DWORD>(remaining), &read, nullptr);
            // Capture immediately: when ReadFile succeeds but returns 0 bytes,
            // GetLastError is stale, and the printed code must not imply a
            // failure that did not happen.
            const DWORD read_error = read_ok ? ERROR_SUCCESS : GetLastError();
            if (!read_ok || read == 0)
            {
                fwprintf(stderr, L"%lsFailed to read runtime: 0x%08X (%zu of %zu bytes)%ls\n", kRed, read_error, total, bytes.size(), kReset);
                bytes.clear();
                return false;
            }
            total += read;
        }
        return true;
    }

    bool VerifyRuntimeBytes(const std::vector<BYTE> & bytes)
    {
        PE_IMAGE::OPTIONS options;
        options.RequireDll = true;
        options.RequireExports = true;
        options.EnableExceptions = true;
        PE_IMAGE::VIEW view;
        const DWORD validation_result = PE_IMAGE::Validate(bytes.data(), bytes.size(), IMAGE_FILE_MACHINE_AMD64, options, view);
        if (validation_result != FILE_ERR_SUCCESS)
        {
            fwprintf(stderr, L"%lsRuntime DLL PE validation failed: 0x%08X%ls\n", kRed, validation_result, kReset);
            return false;
        }

        constexpr uint32_t expected_words[] =
        {
            AMEGER_RUNTIME_DLL_HASH0,
            AMEGER_RUNTIME_DLL_HASH1,
            AMEGER_RUNTIME_DLL_HASH2,
            AMEGER_RUNTIME_DLL_HASH3,
            AMEGER_RUNTIME_DLL_HASH4,
            AMEGER_RUNTIME_DLL_HASH5,
            AMEGER_RUNTIME_DLL_HASH6,
            AMEGER_RUNTIME_DLL_HASH7
        };
        bool has_embedded_hash = false;
        for (uint32_t word : expected_words)
        {
            has_embedded_hash = has_embedded_hash || word != 0;
        }
        if (!has_embedded_hash)
        {
            PrintError(L"The runtime has no embedded SHA-256. Build it with Build\\Create.bat.");
            return false;
        }

        constexpr wchar_t hex[] = L"0123456789ABCDEF";
        std::wstring expected_hash;
        expected_hash.reserve(64);
        for (uint32_t word : expected_words)
        {
            for (int shift = 28; shift >= 0; shift -= 4)
            {
                expected_hash.push_back(hex[(word >> shift) & 0x0F]);
            }
        }

        const std::wstring actual_hash = Sha256Hex(bytes);
        if (actual_hash.empty() || _wcsicmp(actual_hash.c_str(), expected_hash.c_str()) != 0)
        {
            fwprintf(stderr, L"%lsRuntime DLL SHA-256 mismatch. Expected %ls, got %ls%ls\n", kRed, expected_hash.c_str(), actual_hash.c_str(), kReset);
            return false;
        }

        return true;
    }

    // Loads the runtime DLL and resolves its exported functions.
    bool LoadRuntime(Runtime & runtime)
    {
        const std::wstring path = RuntimePath();
        if (path.empty() || !FileExists(path))
        {
            const std::wstring expected = RuntimeFileName();
            PrintError((L"The runtime DLL (" + expected + L") is missing in DLLs\\ next to the executable.").c_str());
            return false;
        }

        HANDLE runtime_file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
        if (runtime_file == INVALID_HANDLE_VALUE)
        {
            fwprintf(stderr, L"%lsFailed to open runtime for verification: 0x%08X%ls\n", kRed, GetLastError(), kReset);
            return false;
        }

        FileHandleGuard runtime_guard(runtime_file);

        std::vector<BYTE> runtime_bytes;
        if (!ReadHandleBytes(runtime_file, runtime_bytes) || !VerifyRuntimeBytes(runtime_bytes))
        {
            return false;
        }

        DWORD load_error = ERROR_SUCCESS;
        {
            StdoutParkGuard park;
            runtime.module = LoadLibraryExW(path.c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
            load_error = GetLastError();
            if (runtime.module)
            {
                // Runtime export names are compile-time XORed (see KcStrings/Core/XorString.h).
                auto exp_mem = XOR_STR_A("CoreExecute");
                runtime.memory_inject = reinterpret_cast<f_Memory_Inject>(GetProcAddress(runtime.module, exp_mem.get()));
                auto exp_sym = XOR_STR_A("CoreSymbolState");
                runtime.get_symbol_state = reinterpret_cast<f_GetSymbolState>(GetProcAddress(runtime.module, exp_sym.get()));
                auto exp_imp = XOR_STR_A("CoreImportState");
                runtime.get_import_state = reinterpret_cast<f_GetImportState>(GetProcAddress(runtime.module, exp_imp.get()));
                auto exp_init = XOR_STR_A("CoreStart");
                runtime.initialize_runtime = reinterpret_cast<f_InitializeRuntime>(GetProcAddress(runtime.module, exp_init.get()));
                auto exp_shut = XOR_STR_A("CoreStop");
                runtime.shutdown_runtime = reinterpret_cast<f_ShutdownRuntime>(GetProcAddress(runtime.module, exp_shut.get()));
                auto exp_dl = XOR_STR_A("CoreFetch");
                runtime.start_download = reinterpret_cast<f_StartDownload>(GetProcAddress(runtime.module, exp_dl.get()));
                auto exp_cb = XOR_STR_A("CoreSetTrace");
                runtime.set_raw_print_callback = reinterpret_cast<f_SetRawPrintCallback>(GetProcAddress(runtime.module, exp_cb.get()));
                auto exp_hij = XOR_STR_A("CoreAcqStats");
                runtime.get_last_hijack_stats = reinterpret_cast<f_GetLastHijackStats>(GetProcAddress(runtime.module, exp_hij.get()));
                auto exp_map = XOR_STR_A("CoreLoadStats");
                runtime.get_last_map_stats = reinterpret_cast<f_GetLastMapStats>(GetProcAddress(runtime.module, exp_map.get()));
                auto exp_str = XOR_STR_A("CoreStrStats");
                runtime.get_last_string_stats = reinterpret_cast<f_GetLastStringStats>(GetProcAddress(runtime.module, exp_str.get()));
                auto exp_tec = XOR_STR_A("CoreExecStats");
                runtime.get_last_thread_exec_stats = reinterpret_cast<f_GetLastThreadExecStats>(GetProcAddress(runtime.module, exp_tec.get()));
                if (runtime.set_raw_print_callback)
                {
                    runtime.set_raw_print_callback(QuietPrint);
                }
            }
        }

        if (!runtime.module)
        {
            fwprintf(stderr, L"%lsFailed to load runtime: %ls (0x%08X)%ls\n", kRed, path.c_str(), load_error, kReset);
            return false;
        }

        if (!runtime.memory_inject || !runtime.get_symbol_state || !runtime.get_import_state || !runtime.initialize_runtime || !runtime.start_download)
        {
            PrintError(L"The runtime DLL does not expose the required functions.");
            return false;
        }

        if (runtime.get_last_hijack_stats)
        {
            if (VerboseOutputEnabled()) { wprintf(L"%ls[+]%ls Telemetry export found.\n\n", kGreen, kReset); }

        }
        else
        {
            wprintf(L"  %ls[!]%ls Telemetry export missing; the Acquire process handle step will show no telemetry.\n", kYellow, kReset);
        }

        // No post-load re-verification: the handle above is opened with
        // FILE_SHARE_READ only, so no writer or deleter can open the file while
        // we hold it. The bytes hashed before LoadLibraryExW are therefore the
        // same bytes the loader maps, and re-reading the same handle would
        // prove nothing.
        return true;
    }

    // Waits for symbol download and import resolution to complete.
    bool WaitForRuntime(const Runtime & runtime, DWORD & symbol_state, DWORD & import_state)
    {
        constexpr ULONGLONG timeout = 120000;

        const DWORD initialization_state = runtime.initialize_runtime();
        if (initialization_state != INJ_ERR_SUCCESS)
        {
            symbol_state = initialization_state;
            import_state = initialization_state;

            return false;
        }

        runtime.start_download();
        symbol_state = runtime.get_symbol_state();
        ULONGLONG deadline = GetTickCount64() + timeout;
        while (symbol_state == INJ_ERR_SYMBOL_INIT_NOT_DONE)
        {
            if (GetTickCount64() >= deadline)
            {
                return false;
            }
            Sleep(10);
            symbol_state = runtime.get_symbol_state();
        }
        if (symbol_state != INJ_ERR_SUCCESS)
        {
            return false;
        }

        import_state = runtime.get_import_state();
        deadline = GetTickCount64() + timeout;
        while (import_state == INJ_ERR_IMPORT_HANDLER_NOT_DONE)
        {
            if (GetTickCount64() >= deadline)
            {
                return false;
            }
            Sleep(10);
            import_state = runtime.get_import_state();
        }
        return import_state == INJ_ERR_SUCCESS;
    }

    bool ReadFileBytes(const std::wstring & path, std::vector<BYTE> & bytes)
    {
        HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE)
        {
            return false;
        }

        LARGE_INTEGER size{};
        if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0 || static_cast<unsigned long long>(size.QuadPart) > PE_IMAGE::MAX_IMAGE_SIZE)
        {
            CloseHandle(file);
            return false;
        }

        bytes.resize(static_cast<size_t>(size.QuadPart));
        size_t total = 0;
        while (total < bytes.size())
        {
            DWORD read = 0;
            const size_t remaining = bytes.size() - total;
            if (!ReadFile(file, bytes.data() + total, static_cast<DWORD>(remaining), &read, nullptr) || read == 0)
            {
                CloseHandle(file);
                bytes.clear();
                return false;
            }
            total += read;
        }

        CloseHandle(file);
        return true;
    }

    // Reads architecture and COM metadata from a PE file.
    // validation_out receives the PE_IMAGE::Validate code on strict-validation
    // failure (FILE_ERR_*), so callers can tell "no relocations" apart from
    // "bad layout" instead of a bare "not usable".
    bool InspectDll(const std::wstring & path, DWORD flags, FileInformation & info, std::vector<BYTE> & bytes, std::wstring & sha256, DWORD * validation_out = nullptr)
    {
        bytes.clear();
        sha256.clear();
        if (!ReadFileBytes(path, bytes) || bytes.size() < sizeof(IMAGE_DOS_HEADER))
        {
            return false;
        }

        IMAGE_DOS_HEADER dos{};
        std::memcpy(&dos, bytes.data(), sizeof(dos));
        if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < 0)
        {
            return false;
        }

        const size_t nt_offset = static_cast<size_t>(dos.e_lfanew);
        if (nt_offset > bytes.size() || bytes.size() - nt_offset < sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER))
        {
            return false;
        }

        DWORD signature = 0;
        std::memcpy(&signature, bytes.data() + nt_offset, sizeof(signature));
        if (signature != IMAGE_NT_SIGNATURE)
        {
            return false;
        }

        IMAGE_FILE_HEADER file_header{};
        std::memcpy(&file_header, bytes.data() + nt_offset + sizeof(DWORD), sizeof(file_header));
        const size_t optional_offset = nt_offset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
        if (file_header.SizeOfOptionalHeader < sizeof(WORD) || optional_offset > bytes.size() || file_header.SizeOfOptionalHeader > bytes.size() - optional_offset)
        {
            return false;
        }

        WORD magic = 0;
        std::memcpy(&magic, bytes.data() + optional_offset, sizeof(magic));
        size_t directory_offset = 0;
        if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        {
            info.architecture = file_header.Machine == IMAGE_FILE_MACHINE_I386 ? Architecture::X86 : Architecture::Unknown;
            directory_offset = offsetof(IMAGE_OPTIONAL_HEADER32, DataDirectory);
        }
        else if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        {
            info.architecture = file_header.Machine == IMAGE_FILE_MACHINE_AMD64 ? Architecture::X64 : Architecture::Unknown;
            directory_offset = offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory);
        }
        else
        {
            return false;
        }

        if (info.architecture == Architecture::Unknown || directory_offset + (static_cast<size_t>(IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR) + 1) * sizeof(IMAGE_DATA_DIRECTORY) > file_header.SizeOfOptionalHeader)
        {
            return false;
        }

        DWORD directory_count = 0;
        const size_t count_offset = directory_offset - sizeof(DWORD);
        std::memcpy(&directory_count, bytes.data() + optional_offset + count_offset, sizeof(directory_count));
        info.dotnet = false;
        if (directory_count > IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR)
        {
            IMAGE_DATA_DIRECTORY com_directory{};
            const size_t com_offset = directory_offset + static_cast<size_t>(IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR) * sizeof(IMAGE_DATA_DIRECTORY);
            std::memcpy(&com_directory, bytes.data() + optional_offset + com_offset, sizeof(com_directory));
            info.dotnet = com_directory.VirtualAddress != 0 && com_directory.Size != 0;
        }

        if (info.architecture == Architecture::X64)
        {
            PE_IMAGE::OPTIONS options;
            options.RequireDll = true;
            options.RequireRelocations = true;
            options.ResolveImports = (flags & (INJ_MM_RESOLVE_IMPORTS | INJ_MM_RUN_DLL_MAIN)) != 0;
            options.ResolveDelayImports = (flags & INJ_MM_RESOLVE_DELAY_IMPORTS) != 0;
            options.EnableExceptions = (flags & INJ_MM_ENABLE_EXCEPTIONS) != 0;
            options.InitializeSecurityCookie = (flags & INJ_MM_INIT_SECURITY_COOKIE) != 0;
            options.ExecuteTls = (flags & INJ_MM_EXECUTE_TLS) != 0;
            PE_IMAGE::VIEW view;
            const DWORD validation_result = PE_IMAGE::Validate(bytes.data(), bytes.size(), IMAGE_FILE_MACHINE_AMD64, options, view);
            if (validation_out)
            {
                *validation_out = validation_result;
            }
            if (validation_result != FILE_ERR_SUCCESS)
            {
                bytes.clear();
                return false;
            }
        }

        sha256 = Sha256Hex(bytes);
        if (sha256.empty())
        {
            bytes.clear();
            return false;
        }
        return true;
    }

    Architecture ProcessArchitecture(HANDLE process)
    {
        using IsWow64Process2Fn = BOOL(WINAPI *)(HANDLE, USHORT *, USHORT *);
        auto k32_name = XOR_STR_W(L"kernel32.dll");
        HMODULE k32_mod = GetModuleHandleW(k32_name.get());
        IsWow64Process2Fn is_wow64_process2 = nullptr;
        if (k32_mod)
        {
            auto wow_name = XOR_STR_A("IsWow64Process2");
            is_wow64_process2 = reinterpret_cast<IsWow64Process2Fn>(GetProcAddress(k32_mod, wow_name.get()));
        }
        if (is_wow64_process2)
        {
            USHORT native_machine = 0;
            USHORT process_machine = 0;
            if (is_wow64_process2(process, &native_machine, &process_machine))
            {
                if (process_machine == IMAGE_FILE_MACHINE_I386)
                {
                    return Architecture::X86;
                }
                if (native_machine == IMAGE_FILE_MACHINE_AMD64)
                {
                    return Architecture::X64;
                }
                if (native_machine == IMAGE_FILE_MACHINE_I386)
                {
                    return Architecture::X86;
                }
            }
        }

        BOOL is_wow64 = FALSE;
        if (IsWow64Process(process, &is_wow64) && is_wow64)
        {
            return Architecture::X86;
        }

        SYSTEM_INFO system_info{};
        GetNativeSystemInfo(&system_info);
        return system_info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ? Architecture::X64 : Architecture::X86;
    }

    bool QueryProcess(DWORD pid, std::wstring & name, Architecture & architecture,
        ULONGLONG * creation_time = nullptr)
    {
        HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!process)
        {
            process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        }
        if (!process)
        {
            return false;
        }

        wchar_t path[MAX_PATH * 2]{};
        DWORD length = static_cast<DWORD>(std::size(path));
        const BOOL queried = QueryFullProcessImageNameW(process, 0, path, &length);
        architecture = ProcessArchitecture(process);
        // Reuse the handle already held for the name query: reading the
        // creation stamp costs no extra OpenProcess (the project deliberately
        // minimizes handle telemetry). The other three FILETIME outputs are
        // required by the API but unused here.
        if (creation_time)
        {
            FILETIME creation_ft{};
            FILETIME exit_ft{};
            FILETIME kernel_ft{};
            FILETIME user_ft{};
            if (GetProcessTimes(process, &creation_ft, &exit_ft, &kernel_ft, &user_ft))
            {
                *creation_time = (static_cast<ULONGLONG>(creation_ft.dwHighDateTime) << 32) |
                    creation_ft.dwLowDateTime;
            }
        }
        CloseHandle(process);
        if (!queried)
        {
            return false;
        }

        const std::wstring full_path(path, length);
        const size_t slash = full_path.find_last_of(L"\\/");
        name = slash == std::wstring::npos ? full_path : full_path.substr(slash + 1);
        return !name.empty();
    }

    std::wstring NormalizeProcessName(std::wstring name)
    {
        const size_t slash = name.find_last_of(L"\\/");
        if (slash != std::wstring::npos)
        {
            name = name.substr(slash + 1);
        }
        if (name.find(L'.') == std::wstring::npos)
        {
            name += L".exe";
        }
        return name;
    }

    DWORD FindProcess(const std::wstring & requested_name)
    {
        const std::wstring name = NormalizeProcessName(requested_name);
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE)
        {
            return 0;
        }

        PROCESSENTRY32W entry{};
        entry.dwSize = sizeof(entry);
        DWORD result = 0;
        if (Process32FirstW(snapshot, &entry))
        {
            do
            {
                if (_wcsicmp(entry.szExeFile, name.c_str()) == 0)
                {
                    result = entry.th32ProcessID;
                    break;
                }
            } while (Process32NextW(snapshot, &entry));
        }

        CloseHandle(snapshot);
        return result;
    }

    bool RefreshTarget(TargetSelection & target)
    {
        if (target.by_name)
        {
            const DWORD pid = FindProcess(target.requested_name);
            if (!pid)
            {
                return false;
            }
            target.pid = pid;
            return QueryProcess(pid, target.name, target.architecture, &target.creation_time);
        }

        return QueryProcess(target.pid, target.name, target.architecture, &target.creation_time);
    }

    bool SelectTarget(const std::wstring & configured_name, TargetSelection & target, bool & cancelled)
    {
        cancelled = false;
        if (configured_name.empty())
        {
            // Fail closed: there is no built-in default target. An empty
            // ProcessName in the config is a configuration error, not a reason
            // to guess a process name.
            PrintError(L"No target process is configured (ProcessName is empty).");
            return false;
        }
        target.requested_name = NormalizeProcessName(configured_name);
        target.by_name = true;
        wprintf(L"%ls[+]%ls Waiting for %ls... (Press Q to quit)\n", kGreen, kReset, target.requested_name.c_str());
        for (;;)
        {
            const DWORD found = FindProcess(target.requested_name);
            if (found && QueryProcess(found, target.name, target.architecture, &target.creation_time))
            {
                target.pid = found;
                wprintf(L"%ls[+]%ls %ls detected | PID: %ls%lu%ls\n", kGreen, kReset, target.name.c_str(), kGreen, static_cast<unsigned long>(found), kReset);
                return true;
            }

            HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
            const DWORD input_wait = (input && input != INVALID_HANDLE_VALUE) ? WaitForSingleObject(input, 50) : WAIT_TIMEOUT;
            if (input_wait == WAIT_OBJECT_0)
            {
                DWORD console_mode = 0;
                if (GetConsoleMode(input, &console_mode))
                {
                    if (_kbhit())
                    {
                        const int key = _getch();
                        if (key == 'q' || key == 'Q')
                        {
                            cancelled = true;
                            return false;
                        }
                    }
                }
                else
                {
                    std::wstring line;
                    if (!std::getline(std::wcin, line))
                    {
                        cancelled = true;
                        return false;
                    }

                    line = TrimText(line);
                    if (line == L"q" || line == L"Q")
                    {
                        cancelled = true;
                        return false;
                    }
                }
            }
            if (std::wcin.eof())
            {
                cancelled = true;
                return false;
            }
            Sleep(50);
        }
    }

    bool IsAbsolutePath(const std::wstring & path)
    {
        if (path.empty())
        {
            return false;
        }

        if (path.size() >= 3 &&
            ((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z')) &&
            path[1] == L':' && (path[2] == L'\\' || path[2] == L'/'))
        {
            return true;
        }

        if (path.size() >= 2 && path[0] == L'\\' && path[1] == L'\\')
        {
            return true;
        }

        return false;
    }

    bool ResolveDllPath(std::wstring & path)
    {
        if (path.empty() || path == L"q" || path == L"Q")
        {
            return false;
        }

        if (!IsAbsolutePath(path))
        {
            const std::wstring directory = ExecutableDirectory();
            if (directory.empty())
            {
                return false;
            }
            path = directory + path;
        }

        std::vector<wchar_t> buffer(MAX_PATH * 4);
        const DWORD length = GetFullPathNameW(path.c_str(), static_cast<DWORD>(buffer.size()), buffer.data(), nullptr);
        if (!length || length >= buffer.size())
        {
            return false;
        }

        path.assign(buffer.data(), length);
        return FileExists(path);
    }

    const wchar_t * ArchitectureName(Architecture architecture)
    {
        switch (architecture)
        {
            case Architecture::X86:
                return L"x86";
            case Architecture::X64:
                return L"x64";
            default:
                return L"unknown";
        }
    }

    DWORD BuildFlags(const WizardConfig & config);

    bool SelectDll(TargetSelection & target, DWORD flags, const std::wstring & expected_sha256, std::wstring & path, FileInformation & info, std::vector<BYTE> & bytes, std::wstring & sha256, bool & cancelled)
    {
        cancelled = false;
        for (;;)
        {
            std::wstring input;
            if (!ReadLine(L"DLL Path (Q to cancel): ", input))
            {
                cancelled = true;
                return false;
            }
            if (input == L"q" || input == L"Q")
            {
                cancelled = true;
                return false;
            }
            path = input;
            if (!ResolveDllPath(path))
            {
                PrintWarning(L"File doesn't exist, try again.");
                continue;
            }

            DWORD validation_code = FILE_ERR_SUCCESS;
            if (!InspectDll(path, flags, info, bytes, sha256, &validation_code))
            {
                if (validation_code != FILE_ERR_SUCCESS)
                {
                    fwprintf(stderr, L"%lsNot a usable DLL (PE validation 0x%08X). Need x64 DLL with relocations, no .NET.%ls\n",
                        kYellow, validation_code, kReset);
                }
                else
                {
                    PrintWarning(L"Not a usable DLL, try again.");
                }
                continue;
            }

            if (!expected_sha256.empty() && _wcsicmp(expected_sha256.c_str(), sha256.c_str()) != 0)
            {
                fwprintf(stderr, L"%lsPayload SHA-256 mismatch. Expected %ls, got %ls%ls\n", kRed, expected_sha256.c_str(), sha256.c_str(), kReset);
                continue;
            }

            if (target.architecture != Architecture::Unknown && info.architecture != target.architecture)
            {
                wprintf(L"Warning: DLL is %ls but target is %ls.\n", ArchitectureName(info.architecture), ArchitectureName(target.architecture));
                bool proceed = false;
                if (!ReadYesNo(L"Continue anyway?", false, proceed))
                {
                    cancelled = true;
                    return false;
                }
                if (!proceed)
                {
                    continue;
                }
            }

            if (info.dotnet)
            {
                PrintError(L".NET assemblies are not supported in this memory-loading build.");
                continue;
            }
            if (info.architecture == Architecture::X86)
            {
                PrintError(L"x86 DLLs are not supported in this x64-only build.");
                continue;
            }

            if (VerboseOutputEnabled()) { wprintf(L"Verified SHA-256: %ls%ls%ls\n", kGreen, sha256.c_str(), kReset); }
            return true;
        }
    }

    DWORD BuildFlags(const WizardConfig & config)
    {
        DWORD flags = 0;
        // Header erasure is the only cloak and is always applied: the PE header
        // at the image base is zeroed after mapping.
        flags |= INJ_ERASE_HEADER;
        if (config.scramble)
        {
            flags |= INJ_SCRAMBLE_DLL_NAME;
        }
        if (config.load_copy)
        {
            flags |= INJ_LOAD_DLL_COPY;
        }
        if (config.handle_hijacking)
        {
            flags |= INJ_HANDLE_HIJACKING;
            if (!config.hijack_scan)
            {
                flags |= INJ_NO_DONOR_SCAN;
            }
            // No direct OpenProcess/OpenThread fallback: with handle hijacking
            // enabled, acquisition is stealth-only and fails closed when no
            // donor qualifies. There is no config switch for this any more.
            if (!config.sponsor_roundtrip)
            {
                flags |= INJ_SKIP_SPONSOR_ROUNDTRIP;
            }
        }
        if (config.run_dllmain)
        {
            flags |= INJ_MM_RUN_DLL_MAIN;
        }
        if (config.page_protections)
        {
            flags |= INJ_MM_SET_PAGE_PROTECTIONS;
        }
        if (config.loader_lock)
        {
            flags |= INJ_MM_RUN_UNDER_LDR_LOCK;
        }
        if (config.exceptions)
        {
            flags |= INJ_MM_ENABLE_EXCEPTIONS;
        }
        if (config.resolve_imports)
        {
            flags |= INJ_MM_RESOLVE_IMPORTS;
        }
        if (config.security_cookie)
        {
            flags |= INJ_MM_INIT_SECURITY_COOKIE;
        }
        if (config.delay_imports)
        {
            flags |= INJ_MM_RESOLVE_DELAY_IMPORTS;
        }
        if (config.clean_data)
        {
            flags |= INJ_MM_CLEAN_DATA_DIR;
        }
        if (config.execute_tls)
        {
            flags |= INJ_MM_EXECUTE_TLS;
        }
        if (config.from_memory)
        {
            flags |= INJ_MM_MAP_FROM_MEMORY;
        }
        return flags;
    }

    // ========================================================================
    // Stealth pipeline debug: prints each step with actual verified results
    // ========================================================================

    // Pads a stage label with dots so every value starts in the same column,
    // keeping the trace readable regardless of label length.
    std::wstring StageLabel(const wchar_t * label, size_t width = 20)
    {
        std::wstring text(label ? label : L"");
        while (text.size() < width)
        {
            text += L'.';
        }
        return text;
    }

    // Same dotted alignment as StageLabel, but with exactly one trailing space
    // so the value is separated from the dots. Prefer this over embedding the
    // space in the caller's format string: StageLabel has no trailing space, and
    // a format that assumed otherwise silently glued the value to the dots.
    // Labels at or over `width` still get the single space, so a long name can
    // never run into its value.
    std::wstring StageField(const wchar_t * label, size_t width = 20)
    {
        return StageLabel(label, width) + L" ";
    }

    std::wstring StageField(const std::wstring & label, size_t width = 20)
    {
        return StageLabel(label.c_str(), width) + L" ";
    }

    // Stage tag "[n]" for the acquisition trace, with only the digits tinted so
    // the bracket scaffolding stays plain (same rule as the restored-hook [x/y]
    // list). Built here rather than spelled into each format string so the tint
    // cannot drift between the many trace lines.
    std::wstring StageTag(int stage)
    {
        wchar_t num[16]{ 0 };
        swprintf_s(num, L"%d", stage);
        return std::wstring(L"[") + kGreen + num + kReset + L"]";
    }

    // Resolves a donor PID to "name (PID x)" for the trace; degrades to the
    // bare PID when the process already exited.
    // Bare process name only (empty when unresolvable). The PID renders
    // at the call site with its own tint so the surrounding parentheses
    // can stay plain like all other scaffolding.
    std::wstring DescribeDonor(DWORD Pid)
    {
        std::wstring Name;
        Architecture Arch = Architecture::Unknown;
        if (Pid && QueryProcess(Pid, Name, Arch) && !Name.empty())
        {
            return Name;
        }

        return std::wstring();
    }

    // Full step-by-step acquisition trace, using the dynamic [n] stage tags
    // (the total is not fixed - it varies with the path taken):
    // every stage the hijack pipeline went through, with the concrete handle
    // values and origins. Context carries interface-side facts (config,
    // privilege, pre-open); Stats carries the runtime side. IsThread selects
    // the thread-sponsor stages (pre-opened / pre-open failed / not attempted)
    // instead of the process-sponsor stages.
    void PrintHijackTrace(const wchar_t * Kind, const HijackStats * Stats, const HijackContext * Context, DWORD Flags, bool IsThread)
    {
        if (!Stats || !Stats->Attempted)
        {
            wprintf(L"  %ls[!]%ls %ls handle: no telemetry (older runtime?).\n", kYellow, kReset, Kind);
            return;
        }

        const bool SponsorUsed = Stats->Success && Stats->Source == static_cast<DWORD>(HijackSource::Sponsor);

        wchar_t Text[256]{ 0 };

        wprintf(L"  %ls acquisition trace:\n\n", Kind);

        int Stage = 0;
        const bool target_known = Context && !Context->TargetName.empty();
        wprintf(L"    %ls %ls %ls%ls%ls, PID %ls%lu%ls\n", StageTag(++Stage).c_str(), StageLabel(L"Target").c_str(),
            target_known ? kGreen : kYellow,
            target_known ? Context->TargetName.c_str() : L"unknown", kReset,
            kGreen, Context ? Context->TargetPid : 0, kReset);

        // The bit is printed from the constant, not a hardcoded "0x0040" baked
        // into the format string, so the two cannot drift apart.
        const DWORD hijack_flag = INJ_HANDLE_HIJACKING;
        const bool hijack_on = (Flags & hijack_flag) != 0;
        const wchar_t * FlagTint = hijack_on ? kGreen : kYellow;
        wprintf(L"    %ls %ls %ls%s%ls (%ls0x%04X%s in flags %ls0x%08X%s)\n", StageTag(++Stage).c_str(),
            StageLabel(L"Config flag").c_str(),
            FlagTint, hijack_on ? L"Y" : L"N", kReset,
            FlagTint, hijack_flag, kReset,
            FlagTint, Flags, kReset);

        if (!IsThread && Context)
        {
            // Three states: the privilege is only attempted when the sponsor
            // open is denied for access, so "not required" (no attempt) must
            // not render as a red FAILED.
            const wchar_t * privilege_text =
                !Context->PrivilegeAttempted ? L"not required" :
                (Context->PrivilegeOk ? L"enabled" : L"FAILED");
            const wchar_t * privilege_tint =
                !Context->PrivilegeAttempted ? kYellow :
                (Context->PrivilegeOk ? kGreen : kRed);
            wprintf(L"    %ls %ls SeDebugPrivilege %ls%s%ls\n", StageTag(++Stage).c_str(), StageLabel(L"Privilege").c_str(),
                privilege_tint, privilege_text, kReset);
        }

        if (IsThread && Context && Context->SponsorThreadOpened)
        {
            wprintf(L"    %ls %ls %ls0x%08X%ls pre-opened, TID %ls0x%04X%ls\n", StageTag(++Stage).c_str(),
                StageLabel(L"Sponsor").c_str(), kGreen, static_cast<DWORD>(Context->SponsorThreadValue), kReset,
                kGreen, Context->SponsorTid, kReset);
        }
        else if (IsThread && Context && Context->SponsorThreadAttempted)
        {
            // The pre-open ran but no live thread could be opened (the snapshot
            // pick raced an exiting thread, or OpenThread was denied). The
            // runtime still searches, so this is a degraded path, not a stop.
            wprintf(L"    %ls %ls %lsFAILED%ls (no valid TID)\n", StageTag(++Stage).c_str(),
                StageLabel(L"Sponsor").c_str(), kRed, kReset);
        }
        else if (IsThread)
        {
            wprintf(L"    %ls %ls %lsnot attempted%ls\n", StageTag(++Stage).c_str(),
                StageLabel(L"Sponsor").c_str(), kYellow, kReset);
        }
        else if (Context && Context->SponsorOpened)
        {
            wprintf(L"    %ls %ls %ls0x%08X%ls pre-opened, mask %ls0x%08X%ls\n", StageTag(++Stage).c_str(),
                StageLabel(L"Sponsor").c_str(), kGreen, static_cast<DWORD>(Context->SponsorValue), kReset,
                kGreen, Context->SponsorAccess, kReset);

            // Verdict words are coloured individually: a FAILED proof must not
            // render green just because it shares a line with an OK one.
            const bool skip_roundtrip = (Flags & INJ_SKIP_SPONSOR_ROUNDTRIP) != 0;
            const wchar_t * RoundTripText =
                Stats->SponsorProbed ? L"OK" : (skip_roundtrip ? L"skipped" : L"FAILED");
            const wchar_t * RoundTripTint =
                Stats->SponsorProbed ? kGreen : (skip_roundtrip ? kGreen : kRed);
            wprintf(L"    %ls %ls identity %ls%s%ls, roundtrip %ls%s%ls\n", StageTag(++Stage).c_str(),
                StageLabel(L"Sponsor proof").c_str(),
                Stats->SponsorValidated ? kGreen : kRed, Stats->SponsorValidated ? L"OK" : L"FAILED", kReset,
                RoundTripTint, RoundTripText, kReset);
        }
        else
        {
            wprintf(L"    %ls %ls %lsnone%ls (donor scan only)\n", StageTag(++Stage).c_str(),
                StageLabel(L"Sponsor").c_str(), kYellow, kReset);
        }

        if (SponsorUsed)
        {
            // The scan never ran, so its counters are zero. Say that instead
            // of printing misleading zeros.
            wprintf(L"    %ls %ls %lsnot required%ls (sponsor satisfied acquisition)\n", StageTag(++Stage).c_str(),
                StageLabel(L"Scan").c_str(), kYellow, kReset);
        }
        else
        {
            wprintf(L"    %ls %ls status %ls0x%08X%ls, %ls%lu%ls handles\n", StageTag(++Stage).c_str(),
                StageLabel(L"Enumeration").c_str(),
                Stats->SnapStatus == 0 ? kGreen : kYellow, Stats->SnapStatus, kReset,
                kGreen, Stats->TotalHandles, kReset);

            wprintf(L"    %ls %ls %ls%s%ls (%ls)\n", StageTag(++Stage).c_str(), StageLabel(L"Calibration").c_str(),
                Stats->Calibrated ? kGreen : kYellow,
                Stats->Calibrated ? L"self-calibrated" : L"uncalibrated", kReset,
                Stats->Calibrated ? L"filtered scan" : L"unfiltered scan");

            // Was missing the trailing kReset, which left the rest of the
            // trace green. Each counter now opens and closes its own span.
            wprintf(L"    %ls %ls examined %ls%lu%ls of %ls%lu%ls, owners %ls%lu%ls, dup-denied %ls%lu%ls, verify-rejected %ls%lu%ls, budget-skipped %ls%lu%ls\n",
                StageTag(++Stage).c_str(), StageLabel(L"Scan").c_str(),
                kGreen, Stats->Examined, kReset, kGreen, Stats->TotalHandles, kReset,
                kGreen, Stats->OwnersOpened, kReset, kGreen, Stats->DupDenied, kReset,
                kGreen, Stats->VerifyRejected, kReset, kGreen, Stats->BudgetSkipped, kReset);
        }

        if (Stats->Success && Stats->DonorPid)
        {
            // Name and PID are separate green values with plain scaffolding:
            // `Name (PID N)`. The old whole-string tint left the parentheses
            // green, and the [self] suffix said nothing the PID doesn't.
            const std::wstring Donor = DescribeDonor(Stats->DonorPid);
            if (!Donor.empty())
            {
                wprintf(L"    %ls %ls %ls%s%ls (PID %ls%lu%ls), handle %ls0x%08X%ls, dup %ls0x%08X%ls\n", StageTag(++Stage).c_str(),
                    StageLabel(L"Donor owner").c_str(), kGreen, Donor.c_str(), kReset,
                    kGreen, Stats->DonorPid, kReset,
                    kGreen, Stats->DonorHandle, kReset, kGreen, Stats->NewHandle, kReset);
            }
            else
            {
                wprintf(L"    %ls %ls PID %ls%lu%ls, handle %ls0x%08X%ls, dup %ls0x%08X%ls\n", StageTag(++Stage).c_str(),
                    StageLabel(L"Donor owner").c_str(),
                    kGreen, Stats->DonorPid, kReset,
                    kGreen, Stats->DonorHandle, kReset, kGreen, Stats->NewHandle, kReset);
            }
        }
        else
        {
            wprintf(L"    %ls %ls %lsnone%ls qualifying\n", StageTag(++Stage).c_str(),
                StageLabel(L"Donor owner").c_str(), kYellow, kReset);
        }

        if (Stats->Success)
        {
            if (Stats->Source == static_cast<DWORD>(HijackSource::Sponsor))
            {
                swprintf_s(Text, L"SPONSOR");
            }
            else
            {
                swprintf_s(Text, L"DONOR SCAN");
            }
            wprintf(L"    %ls %ls %ls%s%ls, granted %ls0x%08X%ls\n", StageTag(++Stage).c_str(), StageLabel(L"Result").c_str(),
                kGreen, Text, kReset, kGreen, Stats->GrantedAccess, kReset);
        }
        else if (Stats->Source == static_cast<DWORD>(HijackSource::Direct))
        {
            wprintf(L"    %ls %ls %lsDIRECT OPEN%ls (code %ls0x%08X%ls)\n", StageTag(++Stage).c_str(),
                StageLabel(L"Result").c_str(), kYellow, kReset, kYellow, Stats->FailCode, kReset);
        }
        else
        {
            wprintf(L"    %ls %ls %lsFAILED%ls (code %ls0x%08X%ls)\n", StageTag(++Stage).c_str(),
                StageLabel(L"Result").c_str(), kRed, kReset, kRed, Stats->FailCode, kReset);
        }

        // Thread-only: a pre-opened sponsor TID is a HINT, not a guarantee. The
        // runtime only reuses it when it can prove the thread is hijackable
        // (not a loader worker, and alertable or Running); a parked
        // non-alertable waiter - the Interface picker's preferred category -
        // cannot be woken by PostThreadMessage and is correctly rejected, after
        // which the donor scan selects a different, actually-hijackable thread.
        // Without this stage the trace showed the requested TID and the result
        // source but never the TID that was actually used, so a legitimate
        // fallback read as a mismatch/failure. Data-driven: it prints only when
        // the sponsor was requested, the scan won, and the used TID differs.
        if (IsThread && Context && Context->SponsorTid && Context->UsedTid
            && Context->UsedTid != Context->SponsorTid && Stats->Success
            && Stats->Source != static_cast<DWORD>(HijackSource::Sponsor))
        {
            wprintf(L"    %ls %ls sponsor TID %ls0x%04lX%ls %lsnot usable%ls; hijacked TID %ls0x%04lX%ls\n",
                StageTag(++Stage).c_str(), StageLabel(L"Fallback").c_str(),
                kGreen, static_cast<unsigned long>(Context->SponsorTid), kReset,
                kYellow, kReset,
                kGreen, static_cast<unsigned long>(Context->UsedTid), kReset);
        }
    }

    // Compact one-line form of the acquisition trace for VerboseTrace = N:
    // outcome only, no per-stage telemetry.
    void PrintHijackSummary(const wchar_t * Kind, const HijackStats * Stats)
    {
        if (!Stats || !Stats->Attempted)
        {
            wprintf(L"  %ls[!]%ls %ls handle: no telemetry (older runtime?).\n", kYellow, kReset, Kind);
            return;
        }

        if (Stats->Success)
        {
            const wchar_t * SourceText = Stats->Source == static_cast<DWORD>(HijackSource::Sponsor) ? L"sponsor"
                : Stats->Source == static_cast<DWORD>(HijackSource::Scan) ? L"scan" : L"direct";
            wprintf(L"  %ls[+]%ls %ls handle acquired via %ls%s%ls (%ls0x%08X%ls)\n", kGreen, kReset, Kind,
                kGreen, SourceText, kReset, kGreen, Stats->NewHandle, kReset);
        }
        else if (Stats->Source == static_cast<DWORD>(HijackSource::Direct))
        {
            wprintf(L"  %ls[+]%ls %ls handle acquired via %lsdirect%s (code %ls0x%08X%ls)\n", kGreen, kReset, Kind,
                kYellow, kReset, kYellow, Stats->FailCode, kReset);
        }
        else
        {
            wprintf(L"  %ls[!]%ls %ls handle failed (code %ls0x%08X%ls)\n", kYellow, kReset, Kind,
                kYellow, Stats->FailCode, kReset);
        }
    }

    // Defined below (next to the hook helpers); surveyed read-only as the
    // last verification step. Forward-declared so the step can be counted
    // in the [n/total] sequence.
    void ReportGameTraps(HANDLE process, DWORD target_pid);

    // String-encryption verification helper for the dedicated step below.
    // Each marker is a literal that must be fully eliminated from the runtime
    // DLL across every tier (single, layered, stack), searched narrow and
    // UTF-16LE. This is a GATE, not a survey: a hit means the obfuscation
    // regressed and the run is failed, because a plaintext ntdll symbol name
    // in .rdata is precisely what an anti-cheat signature scan looks for.
    // The caller reads the runtime DLL once and scans every marker against that
    // single in-memory image, instead of re-reading the file per (marker, width)
    // pair.
    bool BufferContainsMarker(const std::vector<BYTE> & hay, const char * marker, bool wide)
    {
        if (hay.empty() || !marker || !marker[0])
        {
            return false;
        }

        std::vector<BYTE> needle;
        for (const char * c = marker; *c; ++c)
        {
            needle.push_back(static_cast<BYTE>(*c));
            if (wide)
            {
                needle.push_back(0);
            }
        }

        if (hay.size() < needle.size())
        {
            return false;
        }

        for (size_t i = 0; i + needle.size() <= hay.size(); ++i)
        {
            bool hit = true;
            for (size_t j = 0; j < needle.size(); ++j)
            {
                if (hay[i + j] != needle[j])
                {
                    hit = false;
                    break;
                }
            }
            if (hit)
            {
                return true;
            }
        }

        return false;
    }

    bool DebugAndVerifyStealth(HANDLE process, HINSTANCE hRemoteBase, DWORD flags,
        const BYTE * local_pe, size_t local_pe_size, const HijackStats * ProcessHijack, const HijackStats * ThreadHijack,
        const HijackContext * Context, const MAP_STATS * MapStats, f_GetLastStringStats get_string_stats,
        bool survey_game_traps, DWORD survey_pid, bool * wx_violated)
    {
        if (wx_violated)
        {
            *wx_violated = false;
        }

        // Nothing was mapped, so nothing was verified. Fail closed rather than
        // reporting the gate as passed (the old `return true` let a failed map
        // present as a clean injection).
        if (!hRemoteBase)
            return false;

        auto isActive = [flags](DWORD flag) -> bool { return (flags & flag) != 0; };

        // Gate verdict. The string-encryption and forensic-posture steps can
        // flip it; every other step in here is diagnostic and stays non-fatal
        // by design.
        bool string_gate_ok = true;
        bool posture_ok = true;

        int total = 0;
        if (isActive(INJ_HANDLE_HIJACKING)) ++total;
        if (isActive(INJ_MM_RESOLVE_IMPORTS) || isActive(INJ_MM_RUN_DLL_MAIN)) ++total;
        if (isActive(INJ_MM_RESOLVE_DELAY_IMPORTS)) ++total;
        if (isActive(INJ_MM_INIT_SECURITY_COOKIE)) ++total;
        if (isActive(INJ_MM_ENABLE_EXCEPTIONS)) ++total;
        // Unconditional: VEH removal is a code-level stealth change, not tied to a
        // payload flag, so it is always verified/printed.
        ++total;
        if (isActive(INJ_MM_EXECUTE_TLS)) ++total;
        if (isActive(INJ_MM_RUN_DLL_MAIN)) ++total;
        if (isActive(INJ_MM_RUN_UNDER_LDR_LOCK)) ++total;
        if (isActive(INJ_MM_CLEAN_DATA_DIR)) ++total;
        if (isActive(INJ_MM_SET_PAGE_PROTECTIONS)) ++total;
        // W^X is unconditional: RW->RX only, zero RWX in image + hijack split.
        ++total;
        // String encryption is unconditional: markers must be absent from
        // the runtime DLL; loader resolution is the functional proof.
        ++total;
        // Forensic posture is unconditional: export neutrality, mutated
        // section names and a zeroed debug directory, all measured from the
        // shipped runtime file.
        ++total;
        if (isActive(INJ_ERASE_HEADER)) ++total;
        if (survey_game_traps) ++total;

        int step = 0;

        // Helper: parse local PE headers from raw buffer
        auto read_local_nt = [&]() -> std::unique_ptr<BYTE[]>
        {
            if (!local_pe || local_pe_size < sizeof(IMAGE_DOS_HEADER))
                return nullptr;
            BYTE * local_copy = const_cast<BYTE *>(local_pe);
            auto dos = ReCa<IMAGE_DOS_HEADER *>(local_copy);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE)
                return nullptr;
            if (local_pe_size < static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64))
                return nullptr;
            auto nt = ReCa<IMAGE_NT_HEADERS *>(local_copy + dos->e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE)
                return nullptr;
            auto nt_buf = std::make_unique<BYTE[]>(sizeof(IMAGE_NT_HEADERS64));
            memcpy(nt_buf.get(), nt, sizeof(IMAGE_NT_HEADERS64));
            return nt_buf;
        };

        // Helper: read remote NT headers (may fail if header erased)
        auto read_remote_nt = [&]() -> std::unique_ptr<BYTE[]>
        {
            if (!process)
                return nullptr;
            BYTE dos_buf[sizeof(IMAGE_DOS_HEADER)] = { 0 };
            SIZE_T ds = 0;
            if (!ReadProcessMemory(process, hRemoteBase, dos_buf, sizeof(IMAGE_DOS_HEADER), &ds))
                return nullptr;
            auto dos = ReCa<IMAGE_DOS_HEADER *>(dos_buf);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE)
                return nullptr;
            auto nt_buf = std::make_unique<BYTE[]>(sizeof(IMAGE_NT_HEADERS64));
            SIZE_T ns = 0;
            if (!ReadProcessMemory(process, ReCa<BYTE *>(hRemoteBase) + dos->e_lfanew,
                nt_buf.get(), sizeof(IMAGE_NT_HEADERS64), &ns))
                return nullptr;
            auto nt = ReCa<IMAGE_NT_HEADERS *>(nt_buf.get());
            if (nt->Signature != IMAGE_NT_SIGNATURE)
                return nullptr;
            return nt_buf;
        };

        // Use remote if available, otherwise local
        auto nt_buf = read_remote_nt();
        auto local_nt_buf = read_local_nt();
        BYTE * nt_data = nt_buf ? nt_buf.get() : (local_nt_buf ? local_nt_buf.get() : nullptr);

        // Helper: convert an RVA to a file offset within the local PE image.
        // This is critical because local_pe is a raw file buffer — RVAs must
        // be translated via section headers, NOT used as direct offsets.
        // For packed DLLs, RVAs can be far beyond the file buffer,
        // causing access violations if used as direct offsets.
        // Returns static_cast<size_t>(-1) if the RVA is out of bounds.
        auto rva_file_offset = [&](DWORD rva) -> size_t
        {
            if (!local_nt_buf || !local_pe)
                return static_cast<size_t>(-1);
            const auto * lnt = ReCa<const IMAGE_NT_HEADERS64 *>(local_nt_buf.get());
            const auto * dos = ReCa<const IMAGE_DOS_HEADER *>(local_pe);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE)
                return static_cast<size_t>(-1);
            const BYTE * nt_in_file = local_pe + dos->e_lfanew;
            const BYTE * sec_ptr = nt_in_file + sizeof(DWORD) +
                sizeof(IMAGE_FILE_HEADER) + lnt->FileHeader.SizeOfOptionalHeader;
            const WORD section_count = lnt->FileHeader.NumberOfSections;
            // Bounds-check the section table itself
            if (sec_ptr + static_cast<size_t>(section_count) * sizeof(IMAGE_SECTION_HEADER) > local_pe + local_pe_size)
                return static_cast<size_t>(-1);
            for (WORD i = 0; i < section_count; ++i)
            {
                const auto * sec = ReCa<const IMAGE_SECTION_HEADER *>(sec_ptr) + i;
                if (rva >= sec->VirtualAddress &&
                    static_cast<DWORD>(rva - sec->VirtualAddress) < sec->SizeOfRawData)
                {
                    const size_t off = static_cast<size_t>(sec->PointerToRawData) + (rva - sec->VirtualAddress);
                    if (off < local_pe_size)
                        return off;
                    return static_cast<size_t>(-1);
                }
            }
            // RVA might be in headers area
            if (rva < lnt->OptionalHeader.SizeOfHeaders && static_cast<size_t>(rva) < local_pe_size)
                return static_cast<size_t>(rva);
            return static_cast<size_t>(-1);
        };


        // Helper: describe a protection constant
        auto desc = [](DWORD p) -> const wchar_t *
        {
            switch (p)
            {
            case PAGE_EXECUTE_READWRITE: return L"PAGE_EXECUTE_READWRITE";
            case PAGE_EXECUTE_READ:      return L"PAGE_EXECUTE_READ";
            case PAGE_EXECUTE_WRITECOPY: return L"PAGE_EXECUTE_WRITECOPY";
            case PAGE_EXECUTE:           return L"PAGE_EXECUTE";
            case PAGE_READONLY:          return L"PAGE_READONLY";
            case PAGE_READWRITE:         return L"PAGE_READWRITE";
            case PAGE_WRITECOPY:         return L"PAGE_WRITECOPY";
            case PAGE_NOACCESS:          return L"PAGE_NOACCESS";
            default:                     return L"UNKNOWN";
            }
        };

        if (isActive(INJ_HANDLE_HIJACKING))
        {
            ++step;
            wprintf(L"\n\n[%ls%d%ls/%ls%d%ls] Acquire process handle...\n\n", kGreen, step, kReset, kGreen, total, kReset);
            if (!Context || Context->Verbose)
            {
                PrintHijackTrace(L"Process", ProcessHijack, Context, flags, false);
                wprintf(L"\n");
                PrintHijackTrace(L"Thread", ThreadHijack, Context, flags, true);
            }
            else
            {
                PrintHijackSummary(L"Process", ProcessHijack);
                PrintHijackSummary(L"Thread", ThreadHijack);
            }
        }

        if (isActive(INJ_MM_RESOLVE_IMPORTS) || isActive(INJ_MM_RUN_DLL_MAIN))
        {
            ++step;
            wprintf(L"\n\n[%ls%d%ls/%ls%d%ls] Resolve imports...\n\n", kGreen, step, kReset, kGreen, total, kReset);
            // Name the modules instead of printing a bare count: "6 import
            // descriptors" told the reader nothing about what was actually
            // resolved. Each entry reports the module and how many functions
            // it contributes, so a surprising module is obvious at a glance.
            struct ImportEntry { char name[MAX_PATH + 1]; ULONG thunk_count; bool named; };
            ImportEntry imports[64]{};
            int import_count = 0;
            ULONG import_total_thunks = 0;
            const char * import_problem = nullptr;

            if (local_nt_buf)
            {
                auto nt = ReCa<IMAGE_NT_HEADERS *>(local_nt_buf.get());
                if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size > 0)
                {
                    const DWORD import_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
                    const size_t import_off = rva_file_offset(import_rva);
                    if (import_off != static_cast<size_t>(-1) && import_off < local_pe_size)
                    {
                        BYTE * import_desc_addr = const_cast<BYTE *>(local_pe) + import_off;
                        const size_t import_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
                        const size_t max_desc = import_size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
                        const size_t avail_desc = (local_pe_size - import_off) / sizeof(IMAGE_IMPORT_DESCRIPTOR);
                        const size_t desc_limit = (std::min)(max_desc, avail_desc);
                        IMAGE_IMPORT_DESCRIPTOR iid = { 0 };
                        for (size_t i = 0; i < 256 && i < desc_limit; ++i)
                        {
                            memcpy(&iid, import_desc_addr + i * sizeof(iid), sizeof(iid));
                            if (iid.Name == 0)
                                break;
                            if (import_count >= static_cast<int>(sizeof(imports) / sizeof(imports[0])))
                            {
                                import_problem = "descriptor list truncated at 64 entries";
                                break;
                            }

                            ImportEntry & slot = imports[import_count];

                            // Module name lives at iid.Name; bounds-check the RVA
                            // and the string itself before trusting it.
                            const size_t name_off = rva_file_offset(iid.Name);
                            if (name_off != static_cast<size_t>(-1) && name_off < local_pe_size)
                            {
                                const char * name_ptr = reinterpret_cast<const char *>(local_pe) + name_off;
                                const size_t max_len = (std::min)(
                                    static_cast<size_t>(MAX_PATH), local_pe_size - name_off - 1);
                                if (max_len > 0)
                                {
                                    size_t len = 0;
                                    while (len < max_len && name_ptr[len] != '\0')
                                    {
                                        ++len;
                                    }
                                    if (len < max_len)
                                    {
                                        memcpy(slot.name, name_ptr, len + 1);
                                        slot.named = true;
                                    }
                                }
                            }
                            if (!slot.named)
                            {
                                strcpy_s(slot.name, "<unreadable>");
                            }

                            // Count this module's imports by walking its thunk
                            // array (PE32+ only; the runtime is x64-only).
                            const DWORD thunk_rva = iid.OriginalFirstThunk ? iid.OriginalFirstThunk : iid.FirstThunk;
                            const size_t thunk_off = rva_file_offset(thunk_rva);
                            if (thunk_off != static_cast<size_t>(-1) && thunk_off + sizeof(ULONG_PTR) <= local_pe_size)
                            {
                                const size_t thunk_max = (local_pe_size - thunk_off) / sizeof(ULONG_PTR);
                                const ULONG_PTR * thunks = reinterpret_cast<const ULONG_PTR *>(
                                    const_cast<BYTE *>(local_pe) + thunk_off);
                                ULONG seen = 0;
                                for (size_t t = 0; t < thunk_max && t < 4096; ++t)
                                {
                                    if (thunks[t] == 0)
                                        break;
                                    ++seen;
                                }
                                slot.thunk_count = seen;
                                import_total_thunks += seen;
                            }

                            ++import_count;
                        }
                    }
                    else
                    {
                        import_problem = "import directory RVA not file-backed";
                    }
                }
                else
                {
                    import_problem = nullptr;
                }
            }

            if (import_count > 0)
            {
                wprintf(L" %ls[+]%ls %ls%d%ls import descriptor(s), %ls%lu%ls function(s) total.\n",
                    kGreen, kReset, kGreen, import_count, kReset, kGreen,
                    static_cast<unsigned long>(import_total_thunks), kReset);
                // The per-module breakdown names every imported DLL and its
                // thunk count. That is the single most identifying thing this
                // tool prints, so it is verbose-only: the summary above still
                // proves the import table resolved.
                if (VerboseOutputEnabled())
                {
                    wprintf(L"\n");
                    for (int i = 0; i < import_count; ++i)
                    {
                        const char * raw = imports[i].name;
                        wchar_t wide[MAX_PATH + 1]{ 0 };
                        const int wide_len = MultiByteToWideChar(CP_ACP, 0, raw, -1, wide, MAX_PATH + 1);
                        if (wide_len <= 0)
                        {
                            wcscpy_s(wide, L"<unprintable>");
                        }
                        // Dotted fields, same as the acquisition trace, so the
                        // ordinals and module names align on the thunk counts
                        // instead of relying on a hand-tuned %-40ls pad.
                        wchar_t ordinal[8]{ 0 };
                        swprintf_s(ordinal, L"%d.", i + 1);
                        wprintf(L"      %ls%ls%ls%lu%ls thunk(s)\n",
                            StageField(ordinal, 6).c_str(),
                            StageField(wide, 26).c_str(),
                            kGreen, static_cast<unsigned long>(imports[i].thunk_count), kReset);
                    }
                }
            }
            else
            {
                wprintf(L"  %ls[+]%ls No statically linked import descriptors in the payload.\n", kGreen, kReset);
            }

            if (import_problem)
            {
                wchar_t problem_w[MAX_PATH + 1]{ 0 };
                if (MultiByteToWideChar(CP_ACP, 0, import_problem, -1, problem_w, MAX_PATH + 1) <= 0)
                {
                    wcscpy_s(problem_w, L"<unprintable>");
                }
                wprintf(L"  %ls[!]%ls Import survey incomplete: %ls%s%ls\n", kYellow, kReset, kYellow, problem_w, kReset);
            }
        }

        if (isActive(INJ_MM_RESOLVE_DELAY_IMPORTS))
        {
            ++step;
            wprintf(L"\n\n[%ls%d%ls/%ls%d%ls] Resolve delay imports...\n\n", kGreen, step, kReset, kGreen, total, kReset);
            if (local_nt_buf)
            {
                auto nt = ReCa<IMAGE_NT_HEADERS *>(local_nt_buf.get());
                auto & dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
                if (dir.Size > 0)
                    wprintf(L"  %ls[+]%ls Delay-import directory present in payload (%ls%lu%ls bytes).\n",
                        kGreen, kReset, kGreen, dir.Size, kReset);
                else
                    wprintf(L"  %ls[+]%ls No delay-import directory present in module.\n", kGreen, kReset);
            }
            else
            {
                wprintf(L"  %ls[+]%ls No local image to survey.\n", kGreen, kReset);
            }
        }

        if (isActive(INJ_MM_INIT_SECURITY_COOKIE))
        {
            ++step;
            wprintf(L"\n\n[%ls%d%ls/%ls%d%ls] Initialize security cookie...\n\n", kGreen, step, kReset, kGreen, total, kReset);
            if (process && local_nt_buf)
            {
                auto nt = ReCa<IMAGE_NT_HEADERS *>(local_nt_buf.get());
                auto &tls_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
                if (tls_dir.Size > 0)
                {
                    BYTE remote_tls[sizeof(IMAGE_TLS_DIRECTORY64)] = { 0 };
                    SIZE_T ts = 0;
                    if (ReadProcessMemory(process, ReCa<BYTE *>(hRemoteBase) + tls_dir.VirtualAddress,
                        remote_tls, sizeof(IMAGE_TLS_DIRECTORY64), &ts) && ts == sizeof(IMAGE_TLS_DIRECTORY64))
                    {
                        auto tls = ReCa<IMAGE_TLS_DIRECTORY64 *>(remote_tls);
                        wprintf(L"  %ls[+]%ls Security cookie initialized (by design; not measured), TLS Directory VA = %ls0x%016llX%ls\n",
                            kGreen, kReset, kGreen, tls->AddressOfCallBacks, kReset);
                    }
                    else
                    {
                        wprintf(L"  %ls[+]%ls Security cookie initialized within the module (by design; not measured).\n", kGreen, kReset);
                    }
                }
                else
                {
                    wprintf(L"  %ls[+]%ls Security cookie initialized within the module (by design; not measured).\n", kGreen, kReset);
                }
            }
            else
            {
                wprintf(L"  %ls[+]%ls Security cookie initialized within the module (by design; not measured).\n", kGreen, kReset);
            }
        }

        if (isActive(INJ_MM_ENABLE_EXCEPTIONS))
        {
            ++step;
            wprintf(L"\n\n[%ls%d%ls/%ls%d%ls] Enable exceptions (SEH)...\n\n", kGreen, step, kReset, kGreen, total, kReset);
            wprintf(L"  %ls[+]%ls SEH via inverted/function table, zero VEH chain entries (by design; not measured)\n", kGreen, kReset);
            wprintf(L"\n");

            if (local_nt_buf)
            {
                auto nt = ReCa<IMAGE_NT_HEADERS *>(local_nt_buf.get());
                const auto & exception_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
                if (exception_dir.Size)
                {
                    const DWORD entry_count = exception_dir.Size / static_cast<DWORD>(sizeof(RUNTIME_FUNCTION));
                    wprintf(L"  %ls[+]%ls Exception directory    : RVA %ls0x%08X%ls  size %ls0x%08X%ls  %ls%lu%s entry(ies)\n",
                        kGreen, kReset,
                        kGreen, exception_dir.VirtualAddress, kReset,
                        kGreen, exception_dir.Size, kReset,
                        kGreen, static_cast<unsigned long>(entry_count), kReset);

                    const ULONG_PTR remote_table = ReCa<ULONG_PTR>(hRemoteBase) + exception_dir.VirtualAddress;
                    RUNTIME_FUNCTION probe{};
                    SIZE_T got = 0;
                    if (process && ReadProcessMemory(process, ReCa<void *>(remote_table), &probe, sizeof(probe), &got) && got == sizeof(probe))
                    {
                        wprintf(L"  %ls[+]%ls .pdata table     : %ls0x%016llX%ls  first %ls0x%08X%s - %s0x%08X%s\n",
                            kGreen, kReset, kGreen, static_cast<unsigned long long>(remote_table), kReset,
                            kGreen, probe.BeginAddress, kReset, kGreen, probe.EndAddress, kReset);
                    }
                    else
                    {
                        wprintf(L"  %ls[!]%ls .pdata table not readable at 0x%016llX\n", kYellow, kReset,
                            static_cast<unsigned long long>(remote_table));
                    }
                }
                else
                {
                    wprintf(L"  %ls[+]%ls No exception directory present in the payload.\n", kGreen, kReset);
                }
            }

            wprintf(L"\n");
            wprintf(L"  %ls[+]%ls Inverted function table updated for %ls%s%ls (by design; not measured)\n", kGreen, kReset, kGreen, XOR_STR_W(L"RtlAddFunctionTable").get(), kReset);
        }

        // Dedicated, result-based debug for the VEH-removal stealth fix. Keep
        // this in the same step style as the loader/import/W^X verifications:
        // print what the build actually does now, not a promise in prose.
        {
            ++step;
            wprintf(L"\n\n[%ls%d%ls/%ls%d%ls] Verify exception handling...\n\n", kGreen, step, kReset, kGreen, total, kReset);

            wprintf(L"  %ls[+]%ls Launcher VEH shell............ %lsnone by design; not measured%ls\n",
                kGreen, kReset, kGreen, kReset);
            wprintf(L"  %ls[+]%ls Added VEH chain entries........ %ls0%ls (by design; not measured)\n",
                kGreen, kReset, kGreen, kReset);
            wprintf(L"  %ls[+]%ls SEH coverage................... %ls%s%ls\n",
                kGreen, kReset,
                isActive(INJ_MM_ENABLE_EXCEPTIONS) ? kGreen : kYellow,
                isActive(INJ_MM_ENABLE_EXCEPTIONS) ? L"inverted table + function-table fallback active (by design; not measured)"
                                                   : L"disabled; payload exceptions not covered",
                kReset);

            STRING_STATS stealth_fix_stats{};
            if (get_string_stats)
            {
                get_string_stats(&stealth_fix_stats);
            }

            if (get_string_stats && stealth_fix_stats.Reported)
            {
                const bool all_imports =
                    stealth_fix_stats.SymbolsResolved == stealth_fix_stats.SymbolsDeclared;
                wprintf(L"  %ls[+]%ls Encrypted NT imports............ %ls%lu%ls of %ls%lu%ls\n",
                    kGreen, kReset,
                    all_imports ? kGreen : kYellow,
                    static_cast<unsigned long>(stealth_fix_stats.SymbolsResolved), kReset,
                    all_imports ? kGreen : kYellow,
                    static_cast<unsigned long>(stealth_fix_stats.SymbolsDeclared), kReset);
                wprintf(L"  %ls[+]%ls Self-test tiers................. %ls%lu%ls of %ls%lu%ls\n",
                    kGreen, kReset,
                    stealth_fix_stats.TiersPassed == stealth_fix_stats.TiersTotal ? kGreen : kRed,
                    static_cast<unsigned long>(stealth_fix_stats.TiersPassed), kReset,
                    stealth_fix_stats.TiersPassed == stealth_fix_stats.TiersTotal ? kGreen : kRed,
                    static_cast<unsigned long>(stealth_fix_stats.TiersTotal), kReset);
            }
            else
            {
                wprintf(L"  %ls[!]%ls Encrypted NT import counters.... %lsUNAVAILABLE%ls (cannot verify VEH import removal from runtime)\n",
                    kYellow, kReset, kYellow, kReset);
            }

            if (local_nt_buf && isActive(INJ_MM_ENABLE_EXCEPTIONS))
            {
                auto nt = ReCa<IMAGE_NT_HEADERS *>(local_nt_buf.get());
                const auto & exception_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
                if (exception_dir.Size)
                {
                    wprintf(L"  %ls[+]%ls Payload exception data.......... RVA %ls0x%08X%ls, %ls%lu%ls entries\n",
                        kGreen, kReset,
                        kGreen, exception_dir.VirtualAddress, kReset,
                        kGreen, static_cast<unsigned long>(exception_dir.Size / sizeof(RUNTIME_FUNCTION)), kReset);
                }
                else
                {
                    wprintf(L"  %ls[!]%ls Payload exception data.......... none; SEH-only cannot unwind payload exceptions\n",
                        kYellow, kReset);
                }
            }
        }

        if (isActive(INJ_MM_EXECUTE_TLS))
        {
            ++step;
            wprintf(L"\n\n[%ls%d%ls/%ls%d%ls] Execute TLS...\n\n", kGreen, step, kReset, kGreen, total, kReset);
            int tls_callbacks = 0;
            if (local_nt_buf)
            {
                auto nt = ReCa<IMAGE_NT_HEADERS *>(local_nt_buf.get());
                auto &tls_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
                if (tls_dir.Size > 0)
                {
                    BYTE local_tls[sizeof(IMAGE_TLS_DIRECTORY64)] = { 0 };
                    SIZE_T copy_size = sizeof(IMAGE_TLS_DIRECTORY64);
                    if (tls_dir.Size < copy_size)
                        copy_size = static_cast<SIZE_T>(tls_dir.Size);
                    const size_t tls_off = rva_file_offset(tls_dir.VirtualAddress);
                    if (tls_off != static_cast<size_t>(-1) && tls_off + copy_size <= local_pe_size)
                    {
                        memcpy(&local_tls, local_pe + tls_off, copy_size);
                        auto tls = ReCa<IMAGE_TLS_DIRECTORY64 *>(local_tls);
                        if (tls->AddressOfCallBacks)
                        {
                            // AddressOfCallBacks is a VA (preferred image base +
                            // RVA), but rva_file_offset expects an RVA. Subtract
                            // the image base instead of truncating the VA to
                            // 32 bits, which discarded the high half and always
                            // reported zero callbacks.
                            const ULONGLONG image_base = nt->OptionalHeader.ImageBase;
                            const size_t cb_off = tls->AddressOfCallBacks >= image_base
                                ? rva_file_offset(static_cast<DWORD>(tls->AddressOfCallBacks - image_base))
                                : static_cast<size_t>(-1);
                            if (cb_off != static_cast<size_t>(-1))
                            {
                                ULONGLONG * cb_array = ReCa<ULONGLONG *>(const_cast<BYTE *>(local_pe + cb_off));
                                const size_t max_cb = (local_pe_size - cb_off) / sizeof(ULONGLONG);
                                for (size_t i = 0; i < 256 && i < max_cb; ++i)
                                {
                                    if (cb_array[i] == 0 || cb_array[i] == 0xFFFFFFFF)
                                        break;
                                    ++tls_callbacks;
                                }
                            }
                        }
                    }
                }
            }
            if (tls_callbacks > 0)
                wprintf(L"  %ls[+]%ls %ls%d%ls TLS callback(s) found (execution by design; not measured).\n",
                    kGreen, kReset, kGreen, tls_callbacks, kReset);
            else
                // The TLS directory can exist with a non-zero size yet declare
                // no callbacks (AddressOfCallBacks null, or an array whose first
                // entry is null). "directory is empty" was wrong whenever the
                // directory is present, so state what is actually true.
                wprintf(L"  %ls[+]%ls No TLS callbacks present (callback array empty or absent).\n",
                    kGreen, kReset);
        }

        if (isActive(INJ_MM_RUN_DLL_MAIN))
        {
            ++step;
            wprintf(L"\n\n[%ls%d%ls/%ls%d%ls] Execute DllMain...\n\n", kGreen, step, kReset, kGreen, total, kReset);
            wprintf(L"  %ls[+]%ls %lsDllMain(DLL_PROCESS_ATTACH)%ls invocation by design; success inferred from the operation result.\n", kGreen, kReset, kGreen, kReset);
            wprintf(L"  %ls[+]%ls DllMain return value: %lsTRUE%ls (by design; not measured)\n", kGreen, kReset, kGreen, kReset);
        }

        if (isActive(INJ_MM_RUN_UNDER_LDR_LOCK))
        {
            ++step;
            wprintf(L"\n\n[%ls%d%ls/%ls%d%ls] Run under loader lock...\n\n", kGreen, step, kReset, kGreen, total, kReset);
            wprintf(L"  %ls[+]%ls LdrLockLoaderLock acquired (by design; not measured).\n", kGreen, kReset);
            wprintf(L"  %ls[+]%ls LdrUnlockLoaderLock acquired (by design; not measured).\n", kGreen, kReset);
        }

        if (isActive(INJ_MM_CLEAN_DATA_DIR))
        {
            ++step;
            wprintf(L"\n\n[%ls%d%ls/%ls%d%ls] Clean data directories...\n\n", kGreen, step, kReset, kGreen, total, kReset);
            const bool have_shell_report = MapStats &&
                (MapStats->CleanedMask || MapStats->ImportSize || MapStats->DelayImportSize ||
                 MapStats->RelocSize || MapStats->TlsSize || MapStats->DebugSize || MapStats->ExportSize);

            if (have_shell_report)
            {
                // Reported by the shell from inside the target - the only source
                // that survives the header erasure.
                wprintf(L"  %ls[+]%ls Import = %ls%d%ls | DelayImport = %ls%d%ls | Reloc = %ls%d%ls | TLS = %ls%d%ls | Debug = %ls%d%ls | Export = %ls%d%ls\n",
                    kGreen, kReset,
                    kGreen, static_cast<int>((MapStats->CleanedMask >> IMAGE_DIRECTORY_ENTRY_IMPORT) & 1), kReset,
                    kGreen, static_cast<int>((MapStats->CleanedMask >> IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT) & 1), kReset,
                    kGreen, static_cast<int>((MapStats->CleanedMask >> IMAGE_DIRECTORY_ENTRY_BASERELOC) & 1), kReset,
                    kGreen, static_cast<int>((MapStats->CleanedMask >> IMAGE_DIRECTORY_ENTRY_TLS) & 1), kReset,
                    kGreen, static_cast<int>((MapStats->CleanedMask >> IMAGE_DIRECTORY_ENTRY_DEBUG) & 1), kReset,
                    kGreen, static_cast<int>((MapStats->CleanedMask >> IMAGE_DIRECTORY_ENTRY_EXPORT) & 1), kReset);
                wprintf(L"  %ls[+]%ls Pre-clean sizes: Import %ls0x%08X%ls | DelayImport %ls0x%08X%ls | Reloc %ls0x%08X%ls | TLS %ls0x%08X%ls | Debug %ls0x%08X%ls | Export %ls0x%08X%ls\n",
                    kGreen, kReset,
                    kGreen, MapStats->ImportSize, kReset,
                    kGreen, MapStats->DelayImportSize, kReset,
                    kGreen, MapStats->RelocSize, kReset,
                    kGreen, MapStats->TlsSize, kReset,
                    kGreen, MapStats->DebugSize, kReset,
                    kGreen, MapStats->ExportSize, kReset);
                wprintf(L"\n  %ls[+]%ls All data directories zeroed successfully.\n", kGreen, kReset);
            }
            else if (nt_data)
            {
                auto nt = ReCa<IMAGE_NT_HEADERS *>(nt_data);
                wprintf(L"  %ls[+]%ls Import = %ls%d%ls  Reloc = %ls%d%ls  TLS = %ls%d%ls  Exception = %ls%d%ls  Security = %ls%d%ls  Debug = %ls%d%ls  GlobalPtr = %ls%d%ls\n",
                    kGreen, kReset,
                    kGreen, nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0 ? 0 : 1, kReset,
                    kGreen, nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size == 0 ? 0 : 1, kReset,
                    kGreen, nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size == 0 ? 0 : 1, kReset,
                    kGreen, nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size == 0 ? 0 : 1, kReset,
                    kGreen, nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size == 0 ? 0 : 1, kReset,
                    kGreen, nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size == 0 ? 0 : 1, kReset,
                    kGreen, nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_GLOBALPTR].Size == 0 ? 0 : 1, kReset);
                wprintf(L"  %ls[+]%ls All data directories zeroed to prevent static analysis.\n", kGreen, kReset);
            }
            else
            {
                wprintf(L"  %ls[+]%ls All data directories zeroed (by design; not measured).\n", kGreen, kReset);
            }
        }

        if (isActive(INJ_MM_SET_PAGE_PROTECTIONS))
        {
            ++step;
            wprintf(L"\n\n[%ls%d%ls/%ls%d%ls] Set page protections...\n\n", kGreen, step, kReset, kGreen, total, kReset);
            MEMORY_BASIC_INFORMATION mbi = { 0 };
            if (process && VirtualQueryEx(process, hRemoteBase, &mbi, sizeof(mbi)))
            {
                int rwx_count = 0;
                int ro_count = 0;
                int rw_count = 0;
                int rx_count = 0;

                SIZE_T total_image_size = 0;
                if (local_nt_buf)
                {
                    auto nt = ReCa<IMAGE_NT_HEADERS *>(local_nt_buf.get());
                    total_image_size = nt->OptionalHeader.SizeOfImage;
                }

                BYTE * current = ReCa<BYTE *>(hRemoteBase);
                while (true)
                {
                    if (!VirtualQueryEx(process, current, &mbi, sizeof(mbi)))
                        break;
                    if (total_image_size > 0 &&
                        (ReCa<ULONG_PTR>(mbi.BaseAddress) - ReCa<ULONG_PTR>(hRemoteBase)) >= total_image_size)
                        break;
                    if (mbi.Protect != PAGE_NOACCESS && mbi.Protect != 0)
                    {
                        if (mbi.Protect == PAGE_EXECUTE_READWRITE) ++rwx_count;
                        else if (mbi.Protect == PAGE_READONLY)      ++ro_count;
                        else if (mbi.Protect == PAGE_READWRITE)     ++rw_count;
                        else if (mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE) ++rx_count;
                    }
                    current = ReCa<BYTE *>(mbi.BaseAddress) + mbi.RegionSize;
                }
                wprintf(L"  %ls[+]%ls %ls = %ls%d%ls  %ls = %ls%d%ls  %ls = %ls%d%ls  %ls = %ls%d%ls\n",
                    kGreen, kReset,
                    desc(PAGE_EXECUTE_READWRITE), kGreen, rwx_count, kReset,
                    desc(PAGE_READONLY), kGreen, ro_count, kReset,
                    desc(PAGE_READWRITE), kGreen, rw_count, kReset,
                    desc(PAGE_EXECUTE_READ), kGreen, rx_count, kReset);
            }
            else
            {
                wprintf(L"  %ls[+]%ls Section permissions applied to all memory regions (by design; not measured).\n", kGreen, kReset);
            }
        }

        {
            ++step;
            wprintf(L"\n\n[%ls%d%ls/%ls%d%ls] Verify W^X execution (advisory)...\n\n", kGreen, step, kReset, kGreen, total, kReset);

            // Result-based. The old form printed three bare counters, so a scan
            // that died early, or one that walked past the image into unrelated
            // memory, was indistinguishable from a genuinely clean image. These
            // counters answer the question that actually matters: did we cover
            // the whole image, and does the RX count match the sections we know
            // are executable?
            // The section table lives in the file image, NOT in local_nt_buf -
            // that buffer holds only sizeof(IMAGE_NT_HEADERS64) bytes, so the old
            // `(nt + 1)` walk read past the allocation and produced garbage (which
            // is why the executable-section count flip-flopped between 4 and 0).
            // Parse it out of local_pe, which is the whole file.
            auto local_sections = [&](WORD & count) -> const IMAGE_SECTION_HEADER *
            {
                count = 0;
                if (!local_pe || local_pe_size < sizeof(IMAGE_DOS_HEADER))
                {
                    return nullptr;
                }
                auto dos = ReCa<const IMAGE_DOS_HEADER *>(local_pe);
                if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0)
                {
                    return nullptr;
                }
                const size_t nt_off = static_cast<size_t>(dos->e_lfanew);
                if (nt_off + sizeof(IMAGE_NT_HEADERS64) > local_pe_size)
                {
                    return nullptr;
                }
                auto nt = ReCa<const IMAGE_NT_HEADERS64 *>(local_pe + nt_off);
                if (nt->Signature != IMAGE_NT_SIGNATURE)
                {
                    return nullptr;
                }
                const size_t sec_off = nt_off + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) +
                    nt->FileHeader.SizeOfOptionalHeader;
                const WORD n = nt->FileHeader.NumberOfSections;
                if (!n || sec_off + static_cast<size_t>(n) * sizeof(IMAGE_SECTION_HEADER) > local_pe_size)
                {
                    return nullptr;
                }
                count = n;
                return ReCa<const IMAGE_SECTION_HEADER *>(local_pe + sec_off);
            };

            SIZE_T wx_image = 0;
            DWORD wx_exec_sections = 0;
            if (local_nt_buf)
            {
                auto wx_nt = ReCa<IMAGE_NT_HEADERS *>(local_nt_buf.get());
                wx_image = wx_nt->OptionalHeader.SizeOfImage;
            }
            {
                WORD wx_sec_count = 0;
                const IMAGE_SECTION_HEADER * wx_secs = local_sections(wx_sec_count);
                for (WORD s = 0; s < wx_sec_count; ++s)
                {
                    if (wx_secs[s].Characteristics & IMAGE_SCN_MEM_EXECUTE)
                    {
                        ++wx_exec_sections;
                    }
                }
            }

            int wx_rwx = 0;
            int wx_rx = 0;
            int wx_rw = 0;
            int wx_regions = 0;
            SIZE_T wx_bytes = 0;
            std::vector<ULONG_PTR> wx_alloc_bases;
            bool wx_reached_end = false;

            // A handful of offenders is enough to diagnose; the count is exact
            // regardless, only the listing is capped.
            struct WxRegion { ULONG_PTR base; SIZE_T size; };
            WxRegion wx_rwx_list[8]{};
            int wx_rwx_listed = 0;

            MEMORY_BASIC_INFORMATION wx_mbi = { 0 };
            const bool wx_queryable = process != nullptr
                && VirtualQueryEx(process, hRemoteBase, &wx_mbi, sizeof(wx_mbi)) != 0;

            if (wx_queryable && wx_image > 0)
            {
                BYTE * wx_cur = ReCa<BYTE *>(hRemoteBase);
                for (;;)
                {
                    if (!VirtualQueryEx(process, wx_cur, &wx_mbi, sizeof(wx_mbi)))
                        break;
                    if ((ReCa<ULONG_PTR>(wx_mbi.BaseAddress) - ReCa<ULONG_PTR>(hRemoteBase)) >= wx_image)
                    {
                        wx_reached_end = true;
                        break;
                    }
                    ++wx_regions;
                    // Distinct AllocationBase values = distinct VAD/allocation
                    // entries backing the image. A permission change splits a
                    // region but never an allocation, so this counts how many
                    // allocations the load created - the exact number a kernel
                    // VAD-hide must remove. It is the load-shape metric that
                    // matters for the driver phase, and it also catches a
                    // regression if the image is ever mapped in pieces.
                    if (wx_mbi.AllocationBase &&
                        std::find(wx_alloc_bases.begin(), wx_alloc_bases.end(),
                            ReCa<ULONG_PTR>(wx_mbi.AllocationBase)) == wx_alloc_bases.end())
                    {
                        wx_alloc_bases.push_back(ReCa<ULONG_PTR>(wx_mbi.AllocationBase));
                    }
                    if (wx_mbi.State == MEM_COMMIT && wx_mbi.Protect != 0 && wx_mbi.Protect != PAGE_NOACCESS)
                    {
                        wx_bytes += wx_mbi.RegionSize;
                        if (wx_mbi.Protect == PAGE_EXECUTE_READWRITE)
                        {
                            ++wx_rwx;
                            if (wx_rwx_listed < static_cast<int>(sizeof(wx_rwx_list) / sizeof(wx_rwx_list[0])))
                            {
                                wx_rwx_list[wx_rwx_listed].base = ReCa<ULONG_PTR>(wx_mbi.BaseAddress);
                                wx_rwx_list[wx_rwx_listed].size = wx_mbi.RegionSize;
                                ++wx_rwx_listed;
                            }
                        }
                        else if (wx_mbi.Protect == PAGE_EXECUTE_READ || wx_mbi.Protect == PAGE_EXECUTE)
                        {
                            ++wx_rx;
                        }
                        else if (wx_mbi.Protect == PAGE_READWRITE)
                        {
                            ++wx_rw;
                        }
                    }
                    BYTE * wx_next = ReCa<BYTE *>(wx_mbi.BaseAddress) + wx_mbi.RegionSize;
                    if (wx_next <= wx_cur)
                        break;
                    wx_cur = wx_next;
                }

                // Cross-check: every executable section must be mapped executable.
                // Neither a region-count comparison nor a whole-range containment
                // test is valid - the OS merges adjacent same-protection regions,
                // and a section's VirtualSize can exceed its mapped span (packed
                // payloads declare it that way). Query each section's own page.
                int wx_exec_uncovered = 0;
                if (process && wx_image > 0)
                {
                    WORD wx_sec_count = 0;
                    const IMAGE_SECTION_HEADER * wx_secs = local_sections(wx_sec_count);
                    for (WORD s = 0; s < wx_sec_count; ++s)
                    {
                        if (!(wx_secs[s].Characteristics & IMAGE_SCN_MEM_EXECUTE))
                        {
                            continue;
                        }

                        void * sec_addr = ReCa<void *>(ReCa<ULONG_PTR>(hRemoteBase) + wx_secs[s].VirtualAddress);
                        MEMORY_BASIC_INFORMATION sec_mbi{ 0 };
                        const bool exec = VirtualQueryEx(process, sec_addr, &sec_mbi, sizeof(sec_mbi)) != 0
                            && sec_mbi.State == MEM_COMMIT
                            && (sec_mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY));
                        if (!exec)
                        {
                            ++wx_exec_uncovered;
                        }
                    }
                }

                // A missing cross-check (no section table) is not a pass, so it
                // keeps the yellow tint; a real miss must not render green.
                const bool wx_ok = (wx_rwx == 0) && wx_reached_end && (wx_exec_uncovered == 0);
                if (wx_violated)
                {
                    // Reported once, at the end: a W^X violation is a stealth
                    // defect worth surfacing even though it is not the gate.
                    *wx_violated = !wx_ok;
                }
                const wchar_t * RxTint = (wx_exec_sections == 0) ? kYellow
                    : (wx_exec_uncovered ? kRed : kGreen);

                wchar_t RxField[192]{ 0 };
                if (wx_exec_sections > 0)
                {
                    if (wx_exec_uncovered == 0)
                    {
                        // Only the counts carry the tint; the scaffolding stays
                        // plain so a separator never reads as a value.
                        swprintf_s(RxField, L"RX %ls%lu%ls region(s); all %ls%lu%ls executable section(s) are RX",
                            RxTint, static_cast<unsigned long>(wx_rx), kReset,
                            RxTint, static_cast<unsigned long>(wx_exec_sections), kReset);
                    }
                    else
                    {
                        swprintf_s(RxField, L"RX missing for %ls%lu%ls of %ls%lu%ls executable section(s)",
                            RxTint, static_cast<unsigned long>(wx_exec_uncovered), kReset,
                            RxTint, static_cast<unsigned long>(wx_exec_sections), kReset);
                    }
                }
                else
                {
                    swprintf_s(RxField, L"RX %ls%lu%ls region(s), none declared by the section table",
                        RxTint, static_cast<unsigned long>(wx_rx), kReset);
                }

                wprintf(L"  %ls%ls%ls W^X %ls: RWX %ls%d%ls (required %ls0%ls) | %s | RW %ls%d%s\n",
                    wx_ok ? kGreen : kYellow, wx_ok ? L"[+]" : L"[!]", kReset,
                    wx_ok ? L"verified" : L"VIOLATED",
                    wx_ok ? kGreen : kYellow, wx_rwx, kReset,
                    kGreen, kReset,
                    RxField,
                    kGreen, wx_rw, kReset);

                wprintf(L"      %lscoverage%s: %ls%d%s region(s), %ls%lu%s KB of %ls%lu%s KB image, %s%s%s\n",
                    kDim, kReset, kGreen, wx_regions, kReset,
                    kGreen, static_cast<unsigned long>(wx_bytes / 1024), kReset,
                    kGreen, static_cast<unsigned long>(wx_image / 1024), kReset,
                    wx_reached_end ? kReset : kYellow,
                    wx_reached_end ? L"reached end of image" : L"TRUNCATED - image not fully scanned",
                    kReset);

                // Allocation (VAD) entries backing the image, and the resulting
                // private-memory footprint. Region count is page-granular (a
                // protection change splits regions); allocation count is what a
                // kernel hide must unlink. One allocation means the entire image
                // can be removed from a VAD walk with a single operation.
                {
                    const bool single = wx_alloc_bases.size() == 1;
                    wprintf(L"      %lsallocations%s: %ls%zu%s %s(%s %s%s)%s | %lsprivate%s: %ls%zu%s KB\n",
                        kDim, kReset,
                        kGreen, wx_alloc_bases.size(), kReset,
                        single ? kGreen : kYellow,
                        single ? L"single" : L"split across",
                        single ? L"allocation" : L"allocations",
                        single ? kGreen : kYellow,
                        kReset,
                        kDim, kReset,
                        kGreen, static_cast<size_t>(wx_bytes / 1024), kReset);
                }

                for (int i = 0; i < wx_rwx_listed; ++i)
                {
                    wprintf(L"      %lsRWX region at 0x%016llX, %llu bytes%s\n", kYellow,
                        static_cast<unsigned long long>(wx_rwx_list[i].base),
                        static_cast<unsigned long long>(wx_rwx_list[i].size), kReset);
                }
                if (wx_rwx > wx_rwx_listed)
                {
                    wprintf(L"      %ls... and %d more RWX region(s)%s\n", kYellow, wx_rwx - wx_rwx_listed, kReset);
                }
            }
            else if (!wx_queryable)
            {
                // Unknown is not a pass: surface it through the advisory so the
                // verdict line cannot imply a clean W^X scan.
                if (wx_violated)
                {
                    *wx_violated = true;
                }
                wprintf(L"  %ls[!]%ls Image not queryable; W^X state unknown.\n", kYellow, kReset);
            }
            else
            {
                // Without SizeOfImage the walk cannot be bounded, and counting
                // regions of unrelated memory would report a meaningless RX/RW
                // split. Refuse to guess - and report unknown, not clean.
                if (wx_violated)
                {
                    *wx_violated = true;
                }
                wprintf(L"  %ls[!]%ls Image size unknown; W^X scan not bounded, result withheld.\n", kYellow, kReset);
            }
        }

        {
            ++step;
            wprintf(L"\n\n[%ls%d%ls/%ls%d%ls] Verify string encryption...\n\n", kGreen, step, kReset, kGreen, total, kReset);
            const std::wstring rt_path = RuntimePath();
            // Every entry is a literal that must not survive anywhere in the
            // shipped runtime DLL. Keep this list in step with the string tiers:
            // add a marker whenever a new sensitive name is introduced as a
            // literal anywhere in the runtime project. The markers are stored as
            // compile-time ciphertext (XOR_STR_A) so this list leaves no plaintext
            // names in the shipped EXE either; each named object below outlives
            // the scan loop, so its .get() pointer stays valid for its duration.
            auto m0 = XOR_STR_A("msdl.microsoft.com/download/symbols");
            auto m1 = XOR_STR_A("NtUserMsgWaitForMultipleObjectsEx");
            auto m2 = XOR_STR_A("LdrpLoadDllInternal");
            auto m3 = XOR_STR_A("ntdll.dll");
            auto m4 = XOR_STR_A("_RTL_INVERTED_FUNCTION_TABLE");
            auto m5 = XOR_STR_A("_INVERTED_FUNCTION_TABLE_USER_MODE");
            auto m6 = XOR_STR_A("_RTL_INVERTED_FUNCTION_TABLE_ENTRY");
            auto m7 = XOR_STR_A("_INVERTED_FUNCTION_TABLE_ENTRY");
            auto m8 = XOR_STR_A("_LDR_DATA_TABLE_ENTRY");
            auto m9 = XOR_STR_A("_LDR_DDAG_NODE");
            auto m10 = XOR_STR_A("_LDRP_PATH_SEARCH_CONTEXT");
            auto m11 = XOR_STR_A("_LDRP_TLS_ENTRY");
            auto m12 = XOR_STR_A("_KTHREAD_STATE");
            auto m13 = XOR_STR_A("_KWAIT_REASON");
            auto m14 = XOR_STR_A("_KUSER_SHARED_DATA");
            auto m15 = XOR_STR_A("SameTebFlags");
            auto m16 = XOR_STR_A("ProcessEnvironmentBlock");
            auto m17 = XOR_STR_A("LastErrorValue");
            auto m18 = XOR_STR_A("OSBuildNumber");
            auto m19 = XOR_STR_A("FullDllName");
            auto m20 = XOR_STR_A("DdagNode");
            auto m21 = XOR_STR_A("OriginalFullDllName");
            auto m22 = XOR_STR_A("ExceptionDirectory");
            auto m23 = XOR_STR_A("ExceptionDirectorySize");
            auto m24 = XOR_STR_A("SizeOfTable");
            auto m25 = XOR_STR_A("FunctionTable");
            auto m26 = XOR_STR_A("ModuleEntry");
            auto m27 = XOR_STR_A("TableEntry");
            auto m28 = XOR_STR_A("CurrentSize");
            // Proximate-tripwire markers for LOG/plaintext regressions. Kept
            // to strings that are fully avoidable in the shipped image:
            // - bare "ntdll" is NOT gated: the linker's import/ApiSet table
            //   unavoidably carries it (every kernel32-linked binary does).
            //   "ntdll.dll" (m3) remains the gated form and is absent.
            // - "SYMBOL_LOADER" is NOT gated: std::async member-pointer
            //   instantiations bake the C++ class name into mangled symbols
            //   (Fake_no_copy_callable_adapter@P8SYMBOL_LOADER@@...), which
            //   no LOG hygiene can remove short of renaming the class.
            auto m30 = XOR_STR_A("HandleAcq");
            auto m32 = XOR_STR_A("SYMBOL_PARSER");
            auto m33 = XOR_STR_A("DownloadManager");
            auto m34 = XOR_STR_A("TLS_ENTRY");
            auto m35 = XOR_STR_A("PATH_SEARCH_CONTEXT");
            const char * markers[] =
            {
                m0.get(), m1.get(), m2.get(), m3.get(), m4.get(), m5.get(),
                m6.get(), m7.get(), m8.get(), m9.get(), m10.get(), m11.get(),
                m12.get(), m13.get(), m14.get(), m15.get(), m16.get(), m17.get(),
                m18.get(), m19.get(), m20.get(), m21.get(), m22.get(), m23.get(),
                m24.get(), m25.get(), m26.get(), m27.get(), m28.get(),
                m30.get(), m32.get(), m33.get(), m34.get(), m35.get(),
            };
            const size_t marker_count = sizeof(markers) / sizeof(markers[0]);
            // Read the runtime DLL once; every marker (narrow and wide) is
            // scanned against this single in-memory image.
            std::vector<BYTE> rt_bytes;
            const bool rt_read = !rt_path.empty() && ReadFileBytes(rt_path, rt_bytes);
            int marker_found = 0;
            if (rt_read)
            {
                for (size_t m = 0; m < marker_count; ++m)
                {
                    const bool hit_narrow = BufferContainsMarker(rt_bytes, markers[m], false);
                    const bool hit_wide = BufferContainsMarker(rt_bytes, markers[m], true);
                    if (hit_narrow || hit_wide)
                    {
                        ++marker_found;
                        std::wstring wide_marker;
                        for (const char * c = markers[m]; *c; ++c)
                        {
                            wide_marker += static_cast<wchar_t>(*c);
                        }
                        wprintf(L"  %ls[x]%ls marker '%ls' FOUND in runtime DLL (narrow %d, wide %d).\n",
                            kRed, kReset, wide_marker.c_str(), hit_narrow ? 1 : 0, hit_wide ? 1 : 0);
                    }
                }
            }
            if (rt_path.empty())
            {
                wprintf(L"  %ls[x]%ls Runtime path unknown; disk-marker check could not run.\n", kRed, kReset);
                string_gate_ok = false;
            }
            else if (!rt_read)
            {
                wprintf(L"  %ls[x]%ls Runtime DLL unreadable; disk-marker check could not run.\n", kRed, kReset);
                string_gate_ok = false;
            }
            else if (marker_found)
            {
                wprintf(L"  %ls[x]%ls %ls%zu of %zu markers present - string encryption regressed.%ls\n",
                    kRed, kReset, kRed, static_cast<size_t>(marker_found), marker_count, kReset);
                wprintf(L"      These names are plaintext in .rdata and are directly scannable in the target.\n");
                wprintf(L"      A decrypt path that /O2 can constant-fold will always leak here; see\n");
                wprintf(L"      the encrypted-string helper header used by the runtime build.\n");
                string_gate_ok = false;
            }
            else
            {
                wprintf(L"  %ls[+]%ls %ls%zu%ls markers absent from runtime DLL (ciphertext only)\n",
                    kGreen, kReset, kGreen, marker_count, kReset);
            }
            // The three lines below used to assert hardcoded numbers ("30+",
            // "22", "5") that this process could not observe. They are now
            // driven by counters the runtime actually filled in, and an
            // unresolved export is reported as such rather than glossed over.
            STRING_STATS StringStats{};
            if (get_string_stats)
            {
                get_string_stats(&StringStats);
            }

            if (!get_string_stats || !StringStats.Reported)
            {
                wprintf(L"  %ls[!]%ls String-tier counters unavailable from runtime; "
                        L"resolution results not reported.\n", kYellow, kReset);
            }
            else
            {
                const bool all_symbols = StringStats.SymbolsResolved == StringStats.SymbolsDeclared;
                wprintf(L"  %ls[+]%ls NT symbols resolved via encrypted names: %ls%lu%ls of %ls%lu%ls (import %ls%s%ls)\n",
                    kGreen, kReset,
                    all_symbols ? kGreen : kYellow,
                    static_cast<unsigned long>(StringStats.SymbolsResolved), kReset,
                    all_symbols ? kGreen : kYellow,
                    static_cast<unsigned long>(StringStats.SymbolsDeclared), kReset,
                    all_symbols ? kGreen : kYellow,
                    all_symbols ? L"SUCCESS" : L"PARTIAL",
                    kReset);

                wprintf(L"  %ls[+]%ls Encrypted names built from ciphertext, no static table: %ls%lu%ls\n",
                    kGreen, kReset, kGreen,
                    static_cast<unsigned long>(StringStats.HookNamesBuilt), kReset);

                const bool tiers_ok = StringStats.TiersTotal != 0
                    && StringStats.TiersPassed == StringStats.TiersTotal;
                wprintf(L"  %ls[+]%ls self-test tiers passed at import-resolve: %ls%lu%ls of %ls%lu%ls\n",
                    kGreen, kReset,
                    tiers_ok ? kGreen : kRed,
                    static_cast<unsigned long>(StringStats.TiersPassed), kReset,
                    tiers_ok ? kGreen : kRed,
                    static_cast<unsigned long>(StringStats.TiersTotal), kReset);
            }
        }

        {
            ++step;
            wprintf(L"\n\n[%ls%d%ls/%ls%d%ls] Verify forensic posture...\n\n", kGreen, step, kReset, kGreen, total, kReset);
            // Every value below is measured from the shipped runtime file,
            // never asserted from build scripts: neutral export names only,
            // zero standard section names, zeroed debug directory.
            const std::wstring posture_path = RuntimePath();
            std::vector<BYTE> posture_bytes;
            const bool posture_read = !posture_path.empty() && ReadFileBytes(posture_path, posture_bytes);
            size_t export_neutral = 0;
            size_t export_foreign = 0;
            size_t standard_sections = 0;
            DWORD debug_size = 0;
            bool posture_parsed = false;
            if (posture_read && posture_bytes.size() >= sizeof(IMAGE_DOS_HEADER))
            {
                const auto * dos = ReCa<const IMAGE_DOS_HEADER *>(posture_bytes.data());
                if (dos->e_magic == IMAGE_DOS_SIGNATURE && dos->e_lfanew > 0 &&
                    static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) <= posture_bytes.size())
                {
                    const auto * nt = ReCa<const IMAGE_NT_HEADERS64 *>(posture_bytes.data() + dos->e_lfanew);
                    if (nt->Signature == IMAGE_NT_SIGNATURE &&
                        nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC &&
                        nt->FileHeader.NumberOfSections <= 96)
                    {
                        const auto * sections = ReCa<const IMAGE_SECTION_HEADER *>(
                            ReCa<const BYTE *>(&nt->OptionalHeader) + nt->FileHeader.SizeOfOptionalHeader);
                        const size_t table_end = static_cast<size_t>(dos->e_lfanew) + sizeof(DWORD) +
                            sizeof(IMAGE_FILE_HEADER) + nt->FileHeader.SizeOfOptionalHeader +
                            static_cast<size_t>(nt->FileHeader.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER);
                        if (table_end <= posture_bytes.size())
                        {
                            static const char kStandard[][8] =
                            {
                                ".text", ".rdata", ".data", ".pdata",
                                ".rsrc", ".reloc", ".edata", ".idata",
                            };
                            for (WORD s = 0; s < nt->FileHeader.NumberOfSections; ++s)
                            {
                                char name[9] = { 0 };
                                memcpy(name, sections[s].Name, 8);
                                for (size_t k = 0; k < sizeof(kStandard) / sizeof(kStandard[0]); ++k)
                                {
                                    if (strcmp(name, kStandard[k]) == 0)
                                    {
                                        ++standard_sections;
                                        break;
                                    }
                                }
                            }
                            debug_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
                            const DWORD export_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
                            const DWORD export_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
                            posture_parsed = true;
                            if (export_rva && export_size)
                            {
                                auto rva_to_offset = [&](DWORD rva) -> size_t
                                {
                                    for (WORD s = 0; s < nt->FileHeader.NumberOfSections; ++s)
                                    {
                                        const DWORD va = sections[s].VirtualAddress;
                                        const DWORD raw = sections[s].SizeOfRawData;
                                        if (raw && rva >= va && rva - va < raw)
                                        {
                                            const size_t off = static_cast<size_t>(sections[s].PointerToRawData) + (rva - va);
                                            if (off < posture_bytes.size())
                                            {
                                                return off;
                                            }
                                        }
                                    }
                                    return static_cast<size_t>(-1);
                                };
                                const size_t exp_off = rva_to_offset(export_rva);
                                if (exp_off == static_cast<size_t>(-1) || exp_off + 40 > posture_bytes.size())
                                {
                                    posture_parsed = false;
                                }
                                else
                                {
                                    const DWORD num_names = *ReCa<const DWORD *>(posture_bytes.data() + exp_off + 24);
                                    const DWORD addr_names = *ReCa<const DWORD *>(posture_bytes.data() + exp_off + 32);
                                    if (num_names > 256)
                                    {
                                        posture_parsed = false;
                                    }
                                    else
                                    {
                                        for (DWORD i = 0; i < num_names; ++i)
                                        {
                                            const size_t slot = rva_to_offset(addr_names);
                                            if (slot == static_cast<size_t>(-1) ||
                                                slot + static_cast<size_t>(i) * 4 + 4 > posture_bytes.size())
                                            {
                                                posture_parsed = false;
                                                break;
                                            }
                                            const DWORD name_rva = *ReCa<const DWORD *>(
                                                posture_bytes.data() + slot + static_cast<size_t>(i) * 4);
                                            const size_t name_off = rva_to_offset(name_rva);
                                            if (name_off == static_cast<size_t>(-1))
                                            {
                                                posture_parsed = false;
                                                break;
                                            }
                                            size_t len = 0;
                                            while (name_off + len < posture_bytes.size() &&
                                                posture_bytes[name_off + len] && len < 128)
                                            {
                                                ++len;
                                            }
                                            if (name_off + len >= posture_bytes.size())
                                            {
                                                posture_parsed = false;
                                                break;
                                            }
                                            const char * nm = ReCa<const char *>(posture_bytes.data() + name_off);
                                            if (strncmp(nm, "Core", 4) == 0 || strcmp(nm, "g_LibraryState") == 0)
                                            {
                                                ++export_neutral;
                                            }
                                            else
                                            {
                                                ++export_foreign;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if (!posture_read)
            {
                wprintf(L"  %ls[x]%ls Runtime DLL unreadable; posture unverified.\n", kRed, kReset);
                posture_ok = false;
            }
            else if (!posture_parsed)
            {
                wprintf(L"  %ls[x]%ls Runtime image unparseable; posture unverified.\n", kRed, kReset);
                posture_ok = false;
            }
            else
            {
                // Only the verdict is printed by default. The individual
                // counts are diagnostic detail, and an export-name census plus
                // a section census is a precise description of this build.
                if (VerboseOutputEnabled())
                {
                    wprintf(L"  %ls[+]%ls Export names: %ls%zu%ls neutral, %ls%zu%ls foreign\n",
                        kGreen, kReset, kGreen, export_neutral, kReset, kGreen, export_foreign, kReset);
                    wprintf(L"  %ls[+]%ls Standard section names remaining: %ls%zu%ls\n",
                        kGreen, kReset, kGreen, standard_sections, kReset);
                    wprintf(L"  %ls[+]%ls Debug directory size: %ls0x%lX%ls\n",
                        kGreen, kReset, kGreen, static_cast<unsigned long>(debug_size), kReset);
                }
                if (export_foreign || standard_sections || debug_size)
                {
                    wprintf(L"  %ls[x]%ls Forensic posture regressed; rebuild with mutation enabled.\n", kRed, kReset);
                    posture_ok = false;
                }
                else if (!VerboseOutputEnabled())
                {
                    wprintf(L"  %ls[+]%ls Forensic posture clean (detail suppressed; set AMEGER_VERBOSE=1).\n", kGreen, kReset);
                }
            }

            // Payload posture: the loader can only erase what it maps, so the
            // payload's own on-disk shape is the remaining exposure (export
            // names, standard section names, debug directory, and any RWX
            // section characteristic). Measured from the exact bytes that were
            // hashed and mapped - never asserted. Advisory, not gating: the
            // payload is a third-party binary this project does not build, so
            // refusing to run it here would block a pinned, verified payload
            // over a fingerprint we cannot remove from here.
            if (local_pe && local_pe_size)
            {
                PE_IMAGE::VIEW payload_view{};
                const DWORD payload_check = PE_IMAGE::Validate(local_pe, local_pe_size,
                    IMAGE_FILE_MACHINE_AMD64, {}, payload_view);

                size_t payload_exports = 0;
                size_t payload_standard_sections = 0;
                size_t payload_rwx_sections = 0;
                DWORD payload_debug = 0;
                const bool payload_ok = payload_check == FILE_ERR_SUCCESS && payload_view.NtHeaders != nullptr;
                if (payload_ok)
                {
                    static const char kStd[][8] =
                    {
                        ".text", ".rdata", ".data", ".pdata",
                        ".rsrc", ".reloc", ".edata", ".idata",
                    };
                    const IMAGE_SECTION_HEADER * sections = payload_view.Sections;
                    const WORD count = payload_view.NtHeaders->FileHeader.NumberOfSections;
                    for (WORD s = 0; s < count; ++s)
                    {
                        char name[9] = { 0 };
                        memcpy(name, sections[s].Name, 8);
                        for (size_t k = 0; k < sizeof(kStd) / sizeof(kStd[0]); ++k)
                        {
                            if (strcmp(name, kStd[k]) == 0)
                            {
                                ++payload_standard_sections;
                                break;
                            }
                        }
                        if ((sections[s].Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
                            (sections[s].Characteristics & IMAGE_SCN_MEM_WRITE))
                        {
                            ++payload_rwx_sections;
                        }
                    }
                    payload_debug = payload_view.NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;

                    auto rva_to_offset = [&](DWORD rva) -> size_t
                    {
                        for (WORD s = 0; s < count; ++s)
                        {
                            const DWORD va = sections[s].VirtualAddress;
                            const DWORD raw = sections[s].SizeOfRawData;
                            if (raw && rva >= va && rva - va < raw)
                            {
                                const size_t off = static_cast<size_t>(sections[s].PointerToRawData) + (rva - va);
                                if (off < local_pe_size)
                                {
                                    return off;
                                }
                            }
                        }
                        return static_cast<size_t>(-1);
                    };
                    const DWORD exp_rva = payload_view.NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
                    if (exp_rva)
                    {
                        const size_t exp_off = rva_to_offset(exp_rva);
                        if (exp_off != static_cast<size_t>(-1) && exp_off + 40 <= local_pe_size)
                        {
                            payload_exports = *ReCa<const DWORD *>(local_pe + exp_off + 24);
                        }
                    }
                }

// The payload's on-disk census. Reporting it by default hands an observer a
        // complete description of the shipped binary, so only the verdict is
        // printed unless verbose output is requested.
        if (VerboseOutputEnabled())
        {
            wprintf(L"  %ls[+]%ls Payload export names: %ls%zu%ls | standard sections: %ls%zu%ls | RWX sections: %ls%zu%ls | debug: %ls0x%lX%ls\n",
                kGreen, kReset,
                kGreen, payload_exports, kReset,
                kGreen, payload_standard_sections, kReset,
                kGreen, payload_rwx_sections, kReset,
                kGreen, static_cast<unsigned long>(payload_debug), kReset);
        }
        else if (payload_ok)
        {
            wprintf(L"  %ls[+]%ls Payload on-disk posture clean (detail suppressed; set AMEGER_VERBOSE=1).\n", kGreen, kReset);
        }

                if (!payload_ok)
                {
                    wprintf(L"  %ls[!]%ls Payload image could not be re-parsed for a posture report.\n", kYellow, kReset);
                }
                else if (payload_rwx_sections)
                {
                    wprintf(L"  %ls[!]%ls Payload declares RWX section(s); mapped regions may inherit that.\n", kYellow, kReset);
                }
            }
        }

        if (isActive(INJ_ERASE_HEADER))
        {
            ++step;
            wprintf(L"\n\n[%ls%d%ls/%ls%d%ls] Erase PE header...\n\n", kGreen, step, kReset, kGreen, total, kReset);

            SIZE_T header_size = 0;
            if (local_nt_buf)
            {
                auto nt = ReCa<IMAGE_NT_HEADERS *>(local_nt_buf.get());
                header_size = nt->OptionalHeader.SizeOfHeaders;
            }

            constexpr size_t kProbeBytes = 16;
            BYTE header_bytes[kProbeBytes] = { 0 };
            SIZE_T bytesRead = 0;
            const bool read_ok = process &&
                ReadProcessMemory(process, hRemoteBase, header_bytes, kProbeBytes, &bytesRead) && bytesRead == kProbeBytes;

            if (read_ok)
            {
                const ULONGLONG base = static_cast<ULONGLONG>(ReCa<ULONG_PTR>(hRemoteBase));
                wprintf(L"  %ls[+]%ls Image base      : %ls0x%016llX%ls\n",
                    kGreen, kReset, kGreen, base, kReset);

                wchar_t hex[kProbeBytes * 3 + 1] = { 0 };
                const wchar_t digits[] = L"0123456789ABCDEF";
                for (size_t i = 0; i < kProbeBytes; ++i)
                {
                    hex[i * 3 + 0] = digits[header_bytes[i] >> 4];
                    hex[i * 3 + 1] = digits[header_bytes[i] & 0x0F];
                    hex[i * 3 + 2] = L' ';
                }
                hex[kProbeBytes * 3] = L'\0';

                const bool erased = !(header_bytes[0] == 0x4D && header_bytes[1] == 0x5A);
                if (erased)
                {
                    wprintf(L"  %ls[+]%ls First %u bytes  : %ls%ls%ls\n",
                        kGreen, kReset, static_cast<unsigned>(kProbeBytes), kGreen, hex, kReset);
                }
                else
                {
                    wprintf(L"  %ls[!]%ls First %u bytes  : %ls%ls%ls\n",
                        kYellow, kReset, static_cast<unsigned>(kProbeBytes), kYellow, hex, kReset);
                }

                if (header_size)
                {
                    // Addresses and the size value carry green; the
                    // parentheses and the unit stay plain like the prose.
                    wprintf(L"  %ls[+]%ls Header region   : %ls0x%016llX%s - %ls0x%016llX%s (%ls0x%llX%s bytes)\n\n",
                        kGreen, kReset, kGreen, base, kReset, kGreen, base + header_size, kReset,
                        kGreen, static_cast<unsigned long long>(header_size), kReset);
                }

                if (erased)
                {
                    wprintf(L"  %ls[+]%ls MZ header zeroed - signature scan evasion active.\n", kGreen, kReset);
                }
                else
                {
                    wprintf(L"  %ls[!]%ls MZ header still visible at image base.\n", kYellow, kReset);
                }
            }
            else
            {
                wprintf(L"  %ls[!]%ls Image base not readable; header state unknown.\n", kYellow, kReset);
            }
        }
        if (survey_game_traps)
        {
            ++step;
            wprintf(L"\n\n[%ls%d%ls/%ls%d%ls] Survey target traps...\n\n", kGreen, step, kReset, kGreen, total, kReset);
            ReportGameTraps(process, survey_pid);
            wprintf(L"\n");
        }

        return string_gate_ok && posture_ok;
    }

    // Wrapper for DebugAndVerifyStealth with SEH protection.
    // Must be a separate function (no C++ locals with destructors) because
    // __try is incompatible with functions that require object unwinding.
    // A verification fault fails the gate rather than passing it: we could not
    // prove the stealth properties, so we must not report them as holding.
    bool SafeDebugAndVerifyStealth(HANDLE process, HINSTANCE hRemoteBase, DWORD flags,
        const BYTE * local_pe, size_t local_pe_size, const HijackStats * ProcessHijack, const HijackStats * ThreadHijack,
        const HijackContext * Context, const MAP_STATS * MapStats, f_GetLastStringStats get_string_stats,
        bool survey_game_traps, DWORD survey_pid, bool * wx_violated)
    {
        __try
        {
            return DebugAndVerifyStealth(process, hRemoteBase, flags, local_pe, local_pe_size, ProcessHijack, ThreadHijack, Context, MapStats, get_string_stats, survey_game_traps, survey_pid, wx_violated);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            wprintf(L"  %ls[x]%ls Verification faulted; gate cannot be satisfied.\n", kRed, kReset);
            return false;
        }
    }

    constexpr size_t kHookScanBytes = 0x10;

    // Hook survey targets: heap-owned strings built once from compile-time
    // XOR literals (see KcStrings/Core/XorString.h), so .rdata holds ciphertext only.
    // Never store XOR_STR(...).get() in a static -- the temporary dies
    // immediately and dangles. Copy into wstring/string in the same
    // expression instead.
    struct HookTarget
    {
        std::wstring module;
        std::string function;
    };

#define ADD_HOOK_TARGET(vec, mod_lit, fn_lit) do { auto hk_mod = XOR_STR_W(mod_lit); auto hk_fn = XOR_STR_A(fn_lit); (vec).push_back(HookTarget{ hk_mod.get(), hk_fn.get() }); } while (0)

    const std::vector<HookTarget> & GetHookTargets()
    {
        static const std::vector<HookTarget> cached = [] {
            std::vector<HookTarget> list;
            list.reserve(22);
            ADD_HOOK_TARGET(list, L"kernel32.dll", "BaseThreadInitThunk");
            ADD_HOOK_TARGET(list, L"kernel32.dll", "GetModuleHandleW");
            ADD_HOOK_TARGET(list, L"kernel32.dll", "GetProcAddress");
            ADD_HOOK_TARGET(list, L"kernel32.dll", "GetLastError");
            ADD_HOOK_TARGET(list, L"ntdll.dll", "NtOpenFile");
            ADD_HOOK_TARGET(list, L"ntdll.dll", "NtReadFile");
            ADD_HOOK_TARGET(list, L"ntdll.dll", "NtClose");
            ADD_HOOK_TARGET(list, L"ntdll.dll", "NtAllocateVirtualMemory");
            ADD_HOOK_TARGET(list, L"ntdll.dll", "NtProtectVirtualMemory");
            ADD_HOOK_TARGET(list, L"ntdll.dll", "NtFreeVirtualMemory");
            ADD_HOOK_TARGET(list, L"ntdll.dll", "NtDelayExecution");
            ADD_HOOK_TARGET(list, L"ntdll.dll", "RtlAllocateHeap");
            ADD_HOOK_TARGET(list, L"ntdll.dll", "RtlFreeHeap");
            ADD_HOOK_TARGET(list, L"ntdll.dll", "LdrUnloadDll");
            ADD_HOOK_TARGET(list, L"ntdll.dll", "LdrGetProcedureAddress");
            ADD_HOOK_TARGET(list, L"ntdll.dll", "LdrGetDllPath");
            ADD_HOOK_TARGET(list, L"ntdll.dll", "LdrLockLoaderLock");
            ADD_HOOK_TARGET(list, L"ntdll.dll", "LdrUnlockLoaderLock");
            ADD_HOOK_TARGET(list, L"ntdll.dll", "RtlAddVectoredExceptionHandler");
            ADD_HOOK_TARGET(list, L"ntdll.dll", "RtlRemoveVectoredExceptionHandler");
            ADD_HOOK_TARGET(list, L"ntdll.dll", "RtlAddFunctionTable");
            ADD_HOOK_TARGET(list, L"ntdll.dll", "RtlAnsiStringToUnicodeString");
            return list;
        }();
        return cached;
    }

    bool GetRemoteModuleBase(HANDLE process, const wchar_t * module_name, ULONG_PTR & base_out)
    {
        base_out = 0;
        if (!process || !module_name)
        {
            return false;
        }

        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetProcessId(process));
        if (snapshot == INVALID_HANDLE_VALUE)
        {
            return false;
        }

        MODULEENTRY32W entry{};
        entry.dwSize = sizeof(entry);
        bool found = false;
        if (Module32FirstW(snapshot, &entry))
        {
            do
            {
                if (!_wcsicmp(entry.szModule, module_name))
                {
                    base_out = reinterpret_cast<ULONG_PTR>(entry.modBaseAddr);
                    found = base_out != 0;
                    break;
                }
            } while (Module32NextW(snapshot, &entry));
        }

        CloseHandle(snapshot);
        return found;
    }

    // Returns the target's own main module (the executable) from a module
    // snapshot. The trap survey derives its module set from the process instead
    // of a hardcoded allowlist: a fixed set of names is itself an identifying
    // artifact. modBaseSize is the image's mapped extent, which the survey uses
    // as its walk terminator so full coverage stops at the module end instead
    // of running into unrelated allocations after it.
    bool GetRemoteMainModule(HANDLE process, std::wstring & name_out, ULONG_PTR & base_out, SIZE_T & size_out)
    {
        name_out.clear();
        base_out = 0;
        size_out = 0;
        if (!process)
        {
            return false;
        }

        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetProcessId(process));
        if (snapshot == INVALID_HANDLE_VALUE)
        {
            return false;
        }

        MODULEENTRY32W entry{};
        entry.dwSize = sizeof(entry);
        bool found = false;
        if (Module32FirstW(snapshot, &entry))
        {
            // The first module in a snapshot is the process's main executable.
            name_out = entry.szModule;
            base_out = reinterpret_cast<ULONG_PTR>(entry.modBaseAddr);
            size_out = static_cast<SIZE_T>(entry.modBaseSize);
            found = !name_out.empty() && base_out != 0;
        }

        CloseHandle(snapshot);
        return found;
    }

    struct RestoredHook
    {
        std::wstring name;
        unsigned int offset = 0;
    };

    ULONG_PTR ResolveHookTarget(HANDLE process, const HookTarget & target, BYTE * local_bytes_out)
    {
        HMODULE local_module = GetModuleHandleW(target.module.c_str());
        if (!local_module)
        {
            return 0;
        }

        void * local_function = reinterpret_cast<void *>(GetProcAddress(local_module, target.function.c_str()));
        if (!local_function)
        {
            return 0;
        }

        MEMORY_BASIC_INFORMATION local_info{};
        if (!VirtualQuery(local_function, &local_info, sizeof(local_info)) ||
            local_info.AllocationBase != local_module)
        {
            return 0;
        }

        ULONG_PTR remote_base = 0;
        if (!GetRemoteModuleBase(process, target.module.c_str(), remote_base))
        {
            return 0;
        }

        memcpy(local_bytes_out, local_function, kHookScanBytes);

        return remote_base +
            (reinterpret_cast<ULONG_PTR>(local_function) - reinterpret_cast<ULONG_PTR>(local_module));
    }

    // Guard-aware probe: never touch PAGE_GUARD / PAGE_NOACCESS. Reading
    // a Warden-guarded .eid / INT3 page would fire its first-chance VEH
    // and report us; skipping is the stealth-correct behavior.
    bool IsSafeCodePage(HANDLE process, ULONG_PTR address, size_t size)
    {
        if (!process || !address || !size)
        {
            return false;
        }

        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQueryEx(process, reinterpret_cast<void *>(address), &mbi, sizeof(mbi)))
        {
            return false;
        }

        if (mbi.State != MEM_COMMIT)
        {
            return false;
        }

        if ((mbi.Protect & PAGE_GUARD) || (mbi.Protect & PAGE_NOACCESS))
        {
            return false;
        }

        const ULONG_PTR region_end = reinterpret_cast<ULONG_PTR>(mbi.BaseAddress) + mbi.RegionSize;
        if (address + size > region_end)
        {
            return false;
        }

        return true;
    }

    size_t FindHookDifference(HANDLE process, ULONG_PTR remote_function, const BYTE * local_bytes)
    {
        if (!IsSafeCodePage(process, remote_function, kHookScanBytes))
        {
            return static_cast<size_t>(-1);
        }

        BYTE remote_bytes[kHookScanBytes]{};
        SIZE_T bytes_read = 0;
        if (!ReadProcessMemory(process, reinterpret_cast<void *>(remote_function), remote_bytes, sizeof(remote_bytes), &bytes_read) ||
            bytes_read != sizeof(remote_bytes))
        {
            return static_cast<size_t>(-1);
        }

        for (size_t i = 0; i < sizeof(remote_bytes); ++i)
        {
            if (remote_bytes[i] != local_bytes[i])
            {
                return i;
            }
        }

        return sizeof(remote_bytes);
    }

    std::wstring HookDisplayName(const HookTarget & target)
    {
        std::wstring name = target.module;
        name += L" -> ";
        for (char c : target.function)
        {
            name += static_cast<wchar_t>(c);
        }
        return name;
    }

    // Read-only, guard-aware survey of target-module traps (.eid page guards,
    // INT3 trampolines). NEVER writes: restoring a Warden INT3 or unguarding
    // an .eid page would break its VEH emulation and trip IntegrityCk. The
    // unified encrypted-IAT dispatcher and session-rotated string keys are
    // left alone for the same reason — there is no safe static restore.
    // The .eid encrypted core itself is never even read: per the analysis it
    // stays encrypted in memory and decrypts page-by-page on execution, so a
    // survey read would only harvest ciphertext while risking a first-chance
    // VEH on a guarded decrypting page. Its range is resolved from the remote
    // section table and skipped outright (counted, disclosed).
    bool GetRemoteEidRange(HANDLE process, ULONG_PTR base, ULONG_PTR & start_out, ULONG_PTR & end_out)
    {
        start_out = 0;
        end_out = 0;
        if (!process || !base)
        {
            return false;
        }
        IMAGE_DOS_HEADER dos{};
        SIZE_T done = 0;
        if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(base), &dos, sizeof(dos), &done) ||
            done != sizeof(dos) || dos.e_magic != IMAGE_DOS_SIGNATURE)
        {
            return false;
        }
        if (dos.e_lfanew <= 0 || dos.e_lfanew > 0x1000)
        {
            return false;
        }
        DWORD sig = 0;
        if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(base + static_cast<ULONG_PTR>(dos.e_lfanew)),
            &sig, sizeof(sig), &done) || done != sizeof(sig) || sig != IMAGE_NT_SIGNATURE)
        {
            return false;
        }
        const ULONG_PTR file_hdr = base + static_cast<ULONG_PTR>(dos.e_lfanew) + sizeof(DWORD);
        WORD num_sections = 0;
        WORD opt_size = 0;
        if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(file_hdr + 2),
            &num_sections, sizeof(num_sections), &done) || done != sizeof(num_sections))
        {
            return false;
        }
        if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(file_hdr + 16),
            &opt_size, sizeof(opt_size), &done) || done != sizeof(opt_size))
        {
            return false;
        }
        if (!num_sections || num_sections > 96)
        {
            return false;
        }
        const ULONG_PTR sec_table = file_hdr + sizeof(IMAGE_FILE_HEADER) + opt_size;
        for (WORD i = 0; i < num_sections; ++i)
        {
            IMAGE_SECTION_HEADER sec{};
            if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(sec_table + static_cast<ULONG_PTR>(i) * sizeof(sec)),
                &sec, sizeof(sec), &done) || done != sizeof(sec))
            {
                return false;
            }
            char name[9] = { 0 };
            memcpy(name, sec.Name, 8);
            if (strcmp(name, ".eid") == 0)
            {
                const DWORD extent = sec.Misc.VirtualSize ? sec.Misc.VirtualSize : sec.SizeOfRawData;
                if (!extent)
                {
                    return false;
                }
                start_out = base + sec.VirtualAddress;
                end_out = start_out + extent;
                return end_out > start_out;
            }
        }
        return false;
    }

    // Reads an unsigned survey bound from the environment. Unset, unparsable
    // or zero means "no bound" (full coverage). Kept fail-loud: a bound that is
    // actually hit is disclosed in the survey output, never applied silently.
    SIZE_T ReadSurveyBound(const wchar_t * name)
    {
        wchar_t buffer[32] = {};
        const DWORD got = GetEnvironmentVariableW(name, buffer, static_cast<DWORD>(sizeof(buffer) / sizeof(buffer[0])));
        if (got == 0 || got >= sizeof(buffer) / sizeof(buffer[0]))
        {
            return 0;
        }

        wchar_t * end = nullptr;
        const unsigned long long value = wcstoull(buffer, &end, 10);
        if (!end || *end != L'\0')
        {
            return 0;
        }

        return static_cast<SIZE_T>(value);
    }

    void ReportGameTraps(HANDLE process, DWORD target_pid)
    {
        if (!process || !target_pid)
        {
            return;
        }

        // The survey set is generic: only the target's own main module. A fixed
        // list of game-specific names is itself an identifying artifact, so the
        // module is resolved from the process rather than hardcoded.
        struct SurveyModule
        {
            std::wstring name;
            ULONG_PTR base;
            SIZE_T size;
        };
        std::vector<SurveyModule> survey_modules;
        {
            std::wstring main_name;
            ULONG_PTR main_base = 0;
            SIZE_T main_size = 0;
            if (GetRemoteMainModule(process, main_name, main_base, main_size))
            {
                survey_modules.push_back(SurveyModule{ main_name, main_base, main_size });
            }
        }

        // Survey bounds. 0 means "no bound": the walk then covers the whole
        // module image - every committed region and every executable region -
        // so the counts below are totals, not floors. A normal target's image
        // is bounded, so the default (unbounded) is the correct, complete
        // survey; the bounds exist only to cap a pathological address space and
        // are opt-in via the environment. A bound that is actually hit is
        // disclosed loudly below, so it can never masquerade as a total.
        const SIZE_T max_walk_regions = ReadSurveyBound(L"AMEGER_SURVEY_MAX_REGIONS");
        const SIZE_T max_walk_bytes = ReadSurveyBound(L"AMEGER_SURVEY_MAX_MB") * (1u << 20);
        const SIZE_T max_sample_regions = ReadSurveyBound(L"AMEGER_SURVEY_MAX_SAMPLE_REGIONS");
        // Bounded read window: a region is read in chunks of at most this many
        // bytes and counted incrementally, so memory stays flat regardless of
        // how large an executable region is.
        constexpr SIZE_T kSurveyChunkBytes = 0x10000; // 64 KB

        int found = 0;
        for (size_t m = 0; m < survey_modules.size(); ++m)
        {
            const std::wstring & mod = survey_modules[m].name;
            const ULONG_PTR base = survey_modules[m].base;
            const SIZE_T image_size = survey_modules[m].size;
            if (!base)
            {
                continue;
            }

            ++found;

            size_t guarded = 0;
            size_t noaccess = 0;
            size_t guarded_bytes = 0;
            size_t noaccess_bytes = 0;
            size_t sampled = 0;
            size_t exec_regions = 0;
            size_t cc_bytes = 0;
            size_t sample_bytes = 0;
            size_t walked = 0;
            size_t eid_skipped = 0;
            // Disclosure state, all data-driven: the sample-cap line prints only
            // when a cap actually skipped an executable region, and the walk
            // line only when the walk actually stopped before the module end.
            size_t sample_capped = 0;
            bool walk_capped = false;
            bool walk_aborted = false;
            const bool unknown_extent = (image_size == 0);
            ULONG_PTR eid_start = 0;
            ULONG_PTR eid_end = 0;
            const bool has_eid = GetRemoteEidRange(process, base, eid_start, eid_end);

            // Walk terminator: the module image end. Without it a full walk
            // would run into unrelated allocations past the module. If the
            // image extent is unknown the walk is skipped rather than run
            // unbounded, and the walk line discloses why.
            const ULONG_PTR walk_end = unknown_extent ? 0 : (base + image_size);

            std::vector<BYTE> chunk_buf(kSurveyChunkBytes);

            BYTE * cursor = reinterpret_cast<BYTE *>(base);
            size_t regions = 0;
            for (;;)
            {
                if (unknown_extent)
                {
                    walk_aborted = true;
                    break;
                }

                if (max_walk_regions && regions >= max_walk_regions)
                {
                    walk_capped = true;
                    break;
                }

                if (reinterpret_cast<ULONG_PTR>(cursor) >= walk_end)
                {
                    break;
                }

                MEMORY_BASIC_INFORMATION mbi{};
                if (!VirtualQueryEx(process, cursor, &mbi, sizeof(mbi)) || !mbi.RegionSize)
                {
                    walk_aborted = true;
                    break;
                }

                BYTE * next = reinterpret_cast<BYTE *>(mbi.BaseAddress) + mbi.RegionSize;
                if (next <= cursor)
                {
                    walk_aborted = true;
                    break;
                }

                // A region wholly below the image base cannot happen once the
                // cursor starts at base, but guard anyway so a misreported
                // BaseAddress can never walk backwards.
                if (reinterpret_cast<ULONG_PTR>(next) <= base)
                {
                    cursor = next;
                    ++regions;
                    continue;
                }

                if (has_eid)
                {
                    const ULONG_PTR r_start = reinterpret_cast<ULONG_PTR>(mbi.BaseAddress);
                    const ULONG_PTR r_end = reinterpret_cast<ULONG_PTR>(next);
                    if (r_start < eid_end && r_end > eid_start)
                    {
                        ++eid_skipped;
                        cursor = next;
                        ++regions;
                        if (max_walk_bytes && reinterpret_cast<ULONG_PTR>(cursor) - base > max_walk_bytes)
                        {
                            walk_capped = true;
                            break;
                        }
                        continue;
                    }
                }

                if (mbi.State == MEM_COMMIT)
                {
                    ++walked;
                    if (mbi.Protect & PAGE_GUARD)
                    {
                        ++guarded;
                        guarded_bytes += mbi.RegionSize;
                    }
                    else if ((mbi.Protect & 0xFF) == PAGE_NOACCESS)
                    {
                        ++noaccess;
                        noaccess_bytes += mbi.RegionSize;
                    }
                    else if (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
                    {
                        ++exec_regions;
                        if (max_sample_regions && sampled >= max_sample_regions)
                        {
                            ++sample_capped;
                        }
                        else
                        {
                            // Read the WHOLE region in bounded chunks so the
                            // INT3 count is a total over this region, not a
                            // fixed-size sample. A short or failed read stops
                            // this region; the region counts as sampled only if
                            // at least one byte was read.
                            SIZE_T remaining = mbi.RegionSize;
                            BYTE * addr = reinterpret_cast<BYTE *>(mbi.BaseAddress);
                            size_t region_cc = 0;
                            size_t region_read = 0;
                            while (remaining)
                            {
                                const SIZE_T want = remaining < kSurveyChunkBytes ? remaining : kSurveyChunkBytes;
                                SIZE_T got = 0;
                                if (!ReadProcessMemory(process, addr, chunk_buf.data(), want, &got) || !got)
                                {
                                    break;
                                }

                                for (size_t i = 0; i < static_cast<size_t>(got); ++i)
                                {
                                    if (chunk_buf[i] == 0xCC)
                                    {
                                        ++region_cc;
                                    }
                                }

                                region_read += static_cast<size_t>(got);
                                addr += got;
                                remaining -= got;
                                if (got < want)
                                {
                                    break;
                                }
                            }

                            if (region_read)
                            {
                                cc_bytes += region_cc;
                                sample_bytes += region_read;
                                ++sampled;
                            }
                        }
                    }
                }

                cursor = next;
                ++regions;
                if (max_walk_bytes && reinterpret_cast<ULONG_PTR>(cursor) - base > max_walk_bytes)
                {
                    walk_capped = true;
                    break;
                }
            }

            // Per-module verdict first, then the evidence, all on dotted fields
            // so this step lines up with the acquisition trace. The previous
            // form printed "242/8192" for INT3, which reads as a count out of a
            // total but is really bytes inside a capped sample; with full
            // coverage the sample is now the whole executable set.
            // Only the walked count carries green; the verdict tint (yellow
            // only, for the guarded alert state) is closed before the
            // parenthesis so "untrapped (" never inherits green.
            const wchar_t * Verdict = (guarded == 0) ? L"untrapped" : L"guarded";
            const wchar_t * VerdictTint = (guarded == 0) ? L"" : kYellow;
            wprintf(L"  %ls%ls%s%s (%ls%zu%s committed region(s) walked)\n",
                StageField(mod, 24).c_str(),
                VerdictTint, Verdict, kReset,
                kGreen, walked, kReset);

            // Blank line separates the verdict header from its evidence block
            // (guard / no-access / INT3) so the two halves read independently.
            wprintf(L"\n");

            wprintf(L"      %ls%ls%zu%ls region(s), %ls%zu%ls KB\n",
                StageField(L"guard:", 12).c_str(),
                kGreen, guarded, kReset,
                kGreen, static_cast<size_t>(guarded_bytes / 1024), kReset);

            wprintf(L"      %ls%ls%zu%ls region(s), %ls%zu%ls KB\n",
                StageField(L"no-access:", 12).c_str(),
                kGreen, noaccess, kReset,
                kGreen, static_cast<size_t>(noaccess_bytes / 1024), kReset);

            if (eid_skipped)
            {
                wprintf(L"      %ls%ls%zu%ls region(s) skipped (encrypted core, never read)\n",
                    StageField(L"eid:", 12).c_str(),
                    kGreen, eid_skipped, kReset);
            }

            if (sample_bytes)
            {
                const size_t cc_pct = (cc_bytes * 100) / sample_bytes;
                // Counts and the percent value carry green; only the literal
                // % sign stays plain.
                wprintf(L"      %ls%ls%zu%ls of %ls%zu%ls sampled bytes are INT3 (%ls0xCC%ls), %ls%zu%s%%, from %ls%zu%ls of %ls%zu%ls exec region(s)\n",
                    StageField(L"INT3:", 12).c_str(),
                    kGreen, cc_bytes, kReset,
                    kGreen, sample_bytes, kReset,
                    kGreen, kReset,
                    kGreen, cc_pct, kReset,
                    kGreen, sampled, kReset, kGreen, exec_regions, kReset);
                // Only a real sample cap makes the INT3 count a floor; with the
                // default (no cap) every executable region is read, so this is
                // silent and the count above is a total.
                if (sample_capped)
                {
                    // Align under the INT3 value column (6 leading spaces plus the
                    // 12-wide "INT3:" field and its separating space) so this reads
                    // as a continuation of the line above, not a new field.
                    wprintf(L"%*s%ls%zu%ls of %ls%zu%ls exec region(s) not sampled (cap %ls%zu%ls), so the INT3 count is a floor, not a total\n",
                        static_cast<int>(StageField(L"INT3:", 12).size()) + 6, L"",
                        kGreen, sample_capped, kReset,
                        kGreen, exec_regions, kReset,
                        kGreen, max_sample_regions, kReset);
                }
            }
            else
            {
                wprintf(L"      %lsno executable region was readable\n",
                    StageField(L"INT3:", 12).c_str());
            }

            // Data-driven: this line prints only when the walk actually stopped
            // before the module end - a configured cap, or a query failure.
            // Reaching the module end is the normal, complete case and prints
            // nothing.
            if (walk_capped || walk_aborted)
            {
                std::wstring reason;
                const auto append = [&reason](const std::wstring & part)
                {
                    if (!reason.empty())
                    {
                        reason += L" / ";
                    }
                    reason += part;
                };

                if (walk_capped)
                {
                    if (max_walk_regions)
                    {
                        wchar_t part[64] = {};
                        swprintf_s(part, L"cap %ls%zu%ls regions", kGreen, max_walk_regions, kReset);
                        append(part);
                    }
                    if (max_walk_bytes)
                    {
                        wchar_t part[64] = {};
                        swprintf_s(part, L"cap %ls%zu%ls MB", kGreen, static_cast<size_t>(max_walk_bytes >> 20), kReset);
                        append(part);
                    }
                }
                if (walk_aborted)
                {
                    append(unknown_extent ? L"module extent unknown" : L"query failed before module end");
                }

                wprintf(L"%*sregion walk stopped early (%ls); counts are partial\n",
                    static_cast<int>(StageField(L"INT3:", 12).size()) + 6, L"",
                    reason.c_str());
            }

            // Blank line between modules so each block reads separately.
            wprintf(L"\n");
        }

        if (!found)
        {
            wprintf(L"  %ls[!]%ls No target module present; nothing to survey.\n", kYellow, kReset);
        }
    }

    // Restores hooked kernel32/ntdll entry points in the target. Takes an
    // already-open handle that carries PROCESS_VM_OPERATION | PROCESS_VM_READ |
    // PROCESS_VM_WRITE | PROCESS_QUERY_LIMITED_INFORMATION - the caller reuses
    // the sponsor pre-open so no extra OpenProcess is issued here.
    // Scope is deliberately system-DLL-only: game .text/.eid are surveyed
    // read-only via ReportGameTraps and never written.
    // Coverage of one hook scan, so "no foreign hooks found" can state how many
    // targets were actually inspected. Without it, a target that failed to
    // resolve and one that matched the local image are indistinguishable.
    struct HookScanStats
    {
        size_t targets = 0;   // entries in the survey list
        size_t resolved = 0;  // module and function both found in the process
        size_t clean = 0;     // resolved and byte-identical to the local image
        size_t hooked = 0;    // differed, so a restore was attempted
        size_t skipped = 0;   // differed but deliberately left alone
        bool scanned = false; // 0 when there was no process handle
    };

    // Hook restoring rewrites executable code inside the target, so it is
    // treated as a dangerous capability rather than a normal toggle: it stays
    // inert unless the operator sets AMEGER_ALLOW_HOOK_PATCH=1 in the
    // environment of this process. HookRestore=Y alone is not sufficient.
    bool HookPatchExplicitlyAllowed()
    {
        static const bool allowed = []() -> bool
        {
            wchar_t buffer[8] = {};
            const DWORD got = GetEnvironmentVariableW(L"AMEGER_ALLOW_HOOK_PATCH", buffer, 4);
            return (got == 1 && buffer[0] == L'1');
        }();
        return allowed;
    }

    void ScanAndRestoreHooks(HANDLE process, std::vector<RestoredHook> & restored, std::vector<std::wstring> & remaining, HookScanStats & stats)
    {
        restored.clear();
        remaining.clear();
        stats = HookScanStats{};

        // Hard gate. This path WRITES executable code in the target. That is a
        // categorically different act from reading it: a target that integrity-
        // hashes its own text sees the bytes change, and the write also forces
        // PROCESS_VM_WRITE onto the target handle for the duration. It therefore
        // requires BOTH the config flag and an explicit environment override,
        // so it can never be switched on by config alone.
        if (!HookPatchExplicitlyAllowed())
        {
            stats.skipped = stats.targets;
            return;
        }

        // Survey list is heap-owned, built once from XOR literals above.
        const std::vector<HookTarget> & targets = GetHookTargets();
        stats.targets = targets.size();

        if (!process)
        {
            return;
        }
        stats.scanned = true;

        for (const HookTarget & target : targets)
        {
            BYTE local_bytes[kHookScanBytes]{};
            const ULONG_PTR remote_function = ResolveHookTarget(process, target, local_bytes);
            if (!remote_function)
            {
                continue;
            }
            ++stats.resolved;

            const size_t first_diff = FindHookDifference(process, remote_function, local_bytes);
            if (first_diff == static_cast<size_t>(-1) || first_diff == sizeof(local_bytes))
            {
                ++stats.clean;
                continue;
            }

            // Re-check guard immediately before the write: a page that
            // became guarded since the read must not be forced open - the
            // guard exception itself is the tripwire.
            if (!IsSafeCodePage(process, remote_function, sizeof(local_bytes)))
            {
                ++stats.skipped;
                continue;
            }

            // Learn the current protection, then stage the page as writable but
            // NOT executable for the write. Using PAGE_EXECUTE_READWRITE would
            // make the page simultaneously writable and executable, which is
            // precisely the anomaly the W^X audit reports as a failure and what
            // an in-memory integrity scanner looks for. Two transitions
            // (X -> RW, then RW -> X) keep W^X true at every instant.
            MEMORY_BASIC_INFORMATION patch_mbi{};
            if (!VirtualQueryEx(process, reinterpret_cast<void *>(remote_function), &patch_mbi, sizeof(patch_mbi)))
            {
                ++stats.skipped;
                continue;
            }

            const DWORD original_protection =
                patch_mbi.Protect & ~(PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE);

            // Every branch drops the execute bit, including an already-RWX
            // region, so the write window is never writable+executable.
            DWORD staged_protection = PAGE_READWRITE;
            if (original_protection == PAGE_WRITECOPY || original_protection == PAGE_EXECUTE_WRITECOPY)
            {
                staged_protection = PAGE_WRITECOPY;
            }

            DWORD discard_protection = 0;
            if (!VirtualProtectEx(process, reinterpret_cast<void *>(remote_function), sizeof(local_bytes), staged_protection, &discard_protection))
            {
                ++stats.skipped;
                continue;
            }

            SIZE_T bytes_written = 0;
            const bool write_ok =
                WriteProcessMemory(process, reinterpret_cast<void *>(remote_function), local_bytes, sizeof(local_bytes), &bytes_written) &&
                bytes_written == sizeof(local_bytes);

            // Always restore the original protection, including when the write
            // failed, so a partial patch can never leave the page writable.
            DWORD ignored_protection = 0;
            const bool protection_ok =
                VirtualProtectEx(process, reinterpret_cast<void *>(remote_function), sizeof(local_bytes), original_protection, &ignored_protection) != FALSE;

            if (!write_ok || !protection_ok)
            {
                ++stats.skipped;
                continue;
            }

            // Flush after the final protection is in place, not before it.
            FlushInstructionCache(process, reinterpret_cast<void *>(remote_function), sizeof(local_bytes));

            BYTE verify_bytes[kHookScanBytes]{};
            SIZE_T bytes_verified = 0;
            if (!ReadProcessMemory(process, reinterpret_cast<void *>(remote_function), verify_bytes, sizeof(verify_bytes), &bytes_verified) ||
                bytes_verified != sizeof(verify_bytes) ||
                memcmp(verify_bytes, local_bytes, sizeof(verify_bytes)) != 0)
            {
                ++stats.skipped;
                continue;
            }

            ++stats.hooked;
            RestoredHook entry;
            entry.name = HookDisplayName(target);
            entry.offset = static_cast<unsigned int>(first_diff);
            restored.push_back(entry);
        }

        for (const HookTarget & target : targets)
        {
            BYTE local_bytes[kHookScanBytes]{};
            const ULONG_PTR remote_function = ResolveHookTarget(process, target, local_bytes);
            if (!remote_function)
            {
                continue;
            }

            const size_t still_diff = FindHookDifference(process, remote_function, local_bytes);
            if (still_diff != static_cast<size_t>(-1) && still_diff != sizeof(local_bytes))
            {
                remaining.push_back(HookDisplayName(target));
            }
        }
    }

    // One place that prints a hook-scan result, so the pre- and post-injection
    // passes cannot drift. The counts matter: "no foreign hooks found" is only
    // meaningful next to how many targets were resolved, otherwise a scan that
    // resolved nothing at all reads the same as a genuinely clean target.
    void PrintHookScanResult(const wchar_t * Phase, const HookScanStats & stats,
        const std::vector<RestoredHook> & restored, const std::vector<std::wstring> & remaining)
    {
        wprintf(L"  %s scan trace:\n\n", Phase);

        if (!stats.scanned)
        {
            wprintf(L"    %ls%zu%s in list, no process handle - nothing was inspected\n",
                StageField(L"Targets").c_str(), stats.targets, kReset);
            return;
        }

        wprintf(L"    %ls%ls%zu%s\n",
            StageField(L"Targets").c_str(), kGreen, stats.targets, kReset);
        wprintf(L"    %ls%ls%zu%s of %ls%zu%s resolved in the target\n",
            StageField(L"Resolved").c_str(),
            (stats.resolved == stats.targets ? kGreen : kYellow), stats.resolved, kReset,
            kGreen, stats.targets, kReset);
        wprintf(L"    %ls%ls%zu%s already matched the local image\n",
            StageField(L"Clean").c_str(), kGreen, stats.clean, kReset);
        wprintf(L"    %ls%ls%zu%s differed, %s%zu%s left alone\n",
            StageField(L"Hooked").c_str(), kGreen, stats.hooked, kReset,
            (stats.skipped ? kYellow : kGreen), stats.skipped, kReset);

        if (!restored.empty())
        {
            wprintf(L"\n");
            for (size_t i = 0; i < restored.size(); ++i)
            {
                const RestoredHook & entry = restored[i];
                // Same rule as every other [x/y] in this file: both counts
                // carry the tint, only the brackets stay plain. The offset
                // tint depends on the result: +0x00 is the routine entry
                // patch (green, like every other count); a nonzero offset
                // means a deeper inline hook reached a later byte, so it
                // draws yellow instead.
                const wchar_t * offset_tint = entry.offset == 0 ? kGreen : kYellow;
                wprintf(L"      [%ls%zu%s/%ls%zu%s] %s (%ls+0x%02X%s)\n",
                    kGreen, i + 1, kReset, kGreen, restored.size(), kReset, entry.name.c_str(),
                    offset_tint, entry.offset, kReset);
            }
        }

        if (!remaining.empty())
        {
            wprintf(L"    %ls%ls%zu%s still differ after the pass:\n",
                StageField(L"Remaining").c_str(), kYellow, remaining.size(), kReset);
            for (const std::wstring & entry : remaining)
            {
                wprintf(L"      %ls! %s%s\n", kYellow, entry.c_str(), kReset);
            }
        }
    }

    void PrintFailureHint(DWORD code)
    {
        if (code == INJ_ERR_OUT_OF_MEMORY_EXT)
        {
            wprintf(L"Reason: VirtualAllocEx failed in target (Adv 5=ACCESS_DENIED, 998/3E6=NOACCESS).\n");
            wprintf(L"Target is likely protected or blocks remote RW/RX allocations.\n");
            wprintf(L"Staging uses RW->RX (no RWX at birth); image uses RW->RX.\n");
            wprintf(L"Try testing on notepad.exe.\n");
        }
        else if (code == INJ_ERR_CANT_OPEN_PROCESS)
        {
            wprintf(L"Reason: OpenProcess denied. Run elevated.\n");
        }
        else if (code == INJ_MM_ERR_DLLMAIN_FAILED)
        {
            wprintf(L"Reason: the mapping, imports, TLS and loader-lock stages all succeeded; the payload's\n");
            wprintf(L"own DllMain(DLL_PROCESS_ATTACH) returned FALSE, i.e. the payload refused to initialize.\n");
            wprintf(L"This is state/thread dependent, not a mapping fault. Load earlier in the target's startup:\n");
            wprintf(L"relaunch the game and load once the launcher reports its symbol download is complete.\n");
            wprintf(L"A failed attempt also leaves loader bookkeeping in the target that cannot be reclaimed\n");
            wprintf(L"(inverted-table entry, TLS index/block have no removal API and point into the freed\n");
            wprintf(L"image), so relaunch the game before trying again.\n");
        }
        else if (code == INJ_MM_ERR_TLS_CALLBACK_RANGE)
        {
            wprintf(L"Reason: a payload TLS callback pointer/array fell outside the mapped image,\n");
            wprintf(L"so only a prefix of its callbacks ran. This is payload-specific, not a mapping\n");
            wprintf(L"fault. Relaunch the target before trying another payload.\n");
        }
        else if (code == INJ_ERR_HANDLE_HIJACK_FAILED)
        {
            wprintf(L"Reason: handle acquisition found no donor; the path is donor-only and fails closed.\n");
            wprintf(L"Check the handle-acquisition settings in Configuration.ini, or run elevated so the\n");
            wprintf(L"sponsor pre-open succeeds.\n");
        }
        else if (code == SR_HT_ERR_OPEN_REFUSED)
        {
            wprintf(L"Reason: thread handle acquisition found no donor; the path is donor-only and\n");
            wprintf(L"fails closed (there is no direct OpenThread fallback). Run elevated so the sponsor\n");
            wprintf(L"thread pre-open succeeds, or retry while the target is active.\n");
        }
        else if (code == SR_HT_ERR_NO_THREADS)
        {
            wprintf(L"Reason: no usable donor thread found. Retry while the target is active.\n");
        }
        else if (code == SR_ERR_TARGET_EXITED)
        {
            wprintf(L"Reason: the target process exited during loading.\n");
        }
        else if (code == SR_HT_ERR_REMOTE_PENDING_TIMEOUT)
        {
            wprintf(L"Note: the payload timed out, but the thread context was restored automatically.\n");
            wprintf(L"Reason: the victim thread never scheduled the donor stub (State stayed Pending),\n");
            wprintf(L"so the memory-loading shell never started. This is thread selection, not a verification issue:\n");
            wprintf(L"CleanDataDirectories and HookRestore are unrelated - keep them enabled.\n");
            wprintf(L"Relaunch the target before retrying; the runtime now re-validates the sponsor\n");
            wprintf(L"TID (alertable/Running, non-worker) and falls back to its own search on mismatch.\n");
        }
        else if (code == INJ_ERR_WINDOWS_VERSION)
        {
            wprintf(L"Reason: the OS version gate could not identify the Windows release.\n");
            wprintf(L"The runtime requires Windows 11 (build 22000+); this is an environment\n");
            wprintf(L"issue, not a mapping or symbol failure.\n");
        }
        else if (code == INJ_ERR_WINDOWS_BUILD_UNSUPPORTED)
        {
            wprintf(L"Reason: the OS gate rejected the host - Windows 11 (build 22000+) is required\n");
            wprintf(L"and this build is outside the supported families (21H2 22000+, 22H2/23H2 22621+,\n");
            wprintf(L"24H2 26100+, 25H2 26200+; newer builds are forward-mapped). This is an\n");
            wprintf(L"environment issue, not a mapping or symbol failure. Update Windows.\n");
        }
        else
        {
            // Every other code gets a short pointer instead of a bare hex value
            // with no explanation; keep it terse so the common cases above are
            // not buried.
            wprintf(L"Reason: unclassified failure 0x%08lX; see the runtime error header.\n",
                static_cast<unsigned long>(code));
        }
    }

    void PauseBeforeExit()
    {
        wprintf(L"\nPress Enter to exit...\n");
        fflush(stdout);

        // --- Layer-by-layer input buffer clearance ---
        // After answering yes/no prompts via std::wcin and using _getch() in
        // the "Waiting for target" loop, multiple buffering layers may hold
        // stale characters. We clear each layer in order:

        std::wcin.clear();

        // Layer 1: C++ stream buffer (std::wcin's internal get area)
        // in_avail() non-blockingly reports chars already in the buffer.
        std::streamsize avail = std::wcin.rdbuf()->in_avail();
        if (avail > 0)
        {
            std::wcin.ignore(avail, L'\n');
        }

        // Layer 2: C stdio buffer (stdin's FILE* internal buffer)
        clearerr(stdin);
        // MSVC documents fflush(stdin) as discarding the buffered input. It is a
        // deliberate platform extension here, not the ISO-C UB case.
        fflush(stdin);
        std::wcin.clear();

        // Layer 3: Raw console input buffer (events from _getch() in waiting loop)
        HANDLE hInput = GetStdHandle(STD_INPUT_HANDLE);
        DWORD mode = 0;
        if (hInput != INVALID_HANDLE_VALUE && GetConsoleMode(hInput, &mode))
        {
            DWORD events = 0;
            if (GetNumberOfConsoleInputEvents(hInput, &events))
            {
                while (events > 0)
                {
                    INPUT_RECORD rec;
                    DWORD read = 0;
                    if (!ReadConsoleInputW(hInput, &rec, 1, &read) || read == 0)
                        break;
                    GetNumberOfConsoleInputEvents(hInput, &events);
                }
            }
        }

        // Layer 4: Block until user presses Enter
        std::wstring ignored;
        std::getline(std::wcin, ignored);
    }

    void PrintRuntimeFailure(DWORD symbol_state, DWORD import_state)
    {
        // CoreStart (InitializeRuntime) failures are propagated through symbol_state /
        // import_state by WaitForRuntime. Report them as init failures, not
        // as symbol-download failures: 0x4E (BUILD_UNSUPPORTED) previously
        // printed as "Failed to load symbols", sending operators down the
        // wrong path (network/symbols) when the real cause was the OS gate.
        const DWORD init_state = symbol_state != INJ_ERR_SUCCESS ? symbol_state : import_state;
        if (init_state == INJ_ERR_WINDOWS_BUILD_UNSUPPORTED || init_state == INJ_ERR_WINDOWS_VERSION)
        {
            DWORD local_build = 0;
            {
                auto ntdll_name = XOR_STR_W(L"ntdll.dll");
                HMODULE ntdll = GetModuleHandleW(ntdll_name.get());
                if (ntdll)
                {
                    struct RtlOsVersionInfo
                    {
                        ULONG dwOSVersionInfoSize;
                        ULONG dwMajorVersion;
                        ULONG dwMinorVersion;
                        ULONG dwBuildNumber;
                        ULONG dwPlatformId;
                        WCHAR szCSDVersion[128];
                    };
                    using RtlGetVersionFn = LONG(__stdcall *)(RtlOsVersionInfo *);
                    auto api_name = XOR_STR_A("RtlGetVersion");
                    auto rtl_get_version = reinterpret_cast<RtlGetVersionFn>(
                        GetProcAddress(ntdll, api_name.get()));
                    if (rtl_get_version)
                    {
                        RtlOsVersionInfo info{};
                        info.dwOSVersionInfoSize = sizeof(info);
                        if (rtl_get_version(&info) == 0)
                        {
                            local_build = info.dwBuildNumber;
                        }
                    }
                }
            }
            if (local_build)
            {
                fwprintf(stderr, L"%lsUnsupported Windows build: local build %lu (code 0x%08X).%ls\n",
                    kRed, static_cast<unsigned long>(local_build), init_state, kReset);
            }
            else
            {
                fwprintf(stderr, L"%lsUnsupported Windows version (code 0x%08X).%ls\n",
                    kRed, init_state, kReset);
            }
            PrintError(L"Supported: Windows 11 21H2 (22000), 22H2/23H2 (22621-22631), 24H2 (26100+), 25H2 (26200+).");
            PrintError(L"Windows 10 and older builds are not supported by this x64/Win11-only build.");
            PrintError(L"Failed to initialize the runtime (OS gate, not a symbol download failure).");
            return;
        }
        if (symbol_state == INJ_ERR_SYMBOL_INIT_NOT_DONE)
        {
            PrintError(L"Timeout waiting for symbol initialization (120s).");
            PrintError(L"Check internet access and Windows symbol server reachability.");
        }
        else if (symbol_state != INJ_ERR_SUCCESS)
        {
            fwprintf(stderr, L"%lsFailed to load symbols: 0x%08X%ls\n", kRed, symbol_state, kReset);
        }
        else if (import_state == INJ_ERR_IMPORT_HANDLER_NOT_DONE)
        {
            PrintError(L"Timeout waiting for import resolution (120s).");
        }
        else if (import_state != INJ_ERR_SUCCESS)
        {
            fwprintf(stderr, L"%lsFailed to resolve imports: 0x%08X%ls\n", kRed, import_state, kReset);
        }
        PrintError(L"Failed to initialize the runtime or download symbols.");
    }

    // Runs target selection, DLL validation, and injection.
    int RunInteractiveWizard(Runtime & runtime)
    {
        // Bland per-run console title: the default title is the executable
        // path (which names the tool), and window titles are a historical
        // enumeration vector. A fresh random suffix per run leaves no stable
        // title hash; nothing else depends on the title.
        {
            ULONGLONG tick = GetTickCount64();
            tick ^= tick >> 29;
            tick *= 0xBF58476D1CE4E5B9ull;
            tick ^= tick >> 32;
            wchar_t title[16] = { 0 };
            swprintf_s(title, L"Host-%08X", static_cast<unsigned int>(tick & 0xFFFFFFFFu));
            SetConsoleTitleW(title);
        }
        if (!LoadRuntime(runtime))
        {
            PauseBeforeExit();
            return 1;
        }

        wprintf(L"Runtime module base = %ls%p%ls\n", kGreen, reinterpret_cast<void *>(runtime.module), kReset);
        wprintf(L"Execution: %lsThreadDonor%ls\n", kGreen, kReset);
        wprintf(L"Mode: %lsMemoryLoading%ls\n\n", kGreen, kReset);

        WizardConfig config;
        std::wstring config_path;
        bool config_invalid = false;
        const bool config_loaded = LoadWizardConfig(config, config_path, config_invalid);
        if (config_invalid || !config_loaded)
        {
            if (config_path.empty())
            {
                PrintError(L"Configuration.ini is required but was not found. Place it next to the executable or in Build\\.");
            }
            else
            {
                PrintError(L"Configuration.ini is invalid; fix SchemaVersion/ProcessName/PayloadSha256 or restore the file.");
            }
            PauseBeforeExit();
            return 1;
        }
        wprintf(L"%ls[+]%ls Configuration loaded: %ls\n", kGreen, kReset, config_path.c_str());

        wprintf(L"\n");
        wprintf(L"Target: %ls%ls%ls | Timeout: %ls%d%ls ms\n",
            kGreen, config.target_name.c_str(), kReset, kGreen, config.timeout, kReset);
        if (VerboseOutputEnabled()) { wprintf(L"Load flags: %ls0x%08X%ls\n", kGreen, BuildFlags(config), kReset); }

        // Fixed order: prompt for the payload BEFORE waiting for the target.
        // The old order (wait for target -> prompt for DLL -> inject) left a
        // human-length gap during which Eidolon/Warden progressed from early
        // boot to active, which is the #1 trigger for the payload's DllMain
        // refusing with 00400013. Selecting the DLL first means detection is
        // followed immediately by RefreshTarget + sponsor + inject (~ms).
        if (!config.from_memory)
        {
            PrintError(L"LoadFromMemory must be enabled for payload integrity verification.");
            PauseBeforeExit();
            return 1;
        }

        wprintf(L"\n");
        std::wstring dll_path;
        std::wstring payload_sha256;
        std::vector<BYTE> raw_data;
        FileInformation fileInformation;
        {
            // No target yet, so pass a dummy Unknown-arch selection: SelectDll
            // skips its target-vs-payload check in that case and the check is
            // done explicitly after detection below.
            TargetSelection no_target;
            bool dll_cancelled = false;
            if (!SelectDll(no_target, BuildFlags(config), config.expected_payload_sha256,
                dll_path, fileInformation, raw_data, payload_sha256, dll_cancelled))
            {
                if (dll_cancelled)
                {
                    wprintf(L"Cancelled.\n");
                    return 0;
                }
                return 2;
            }
        }

        wprintf(L"\n%ls[+]%ls Downloading Windows symbols...\n", kGreen, kReset);
        DWORD symbol_state = INJ_ERR_SYMBOL_INIT_NOT_DONE;
        DWORD import_state = INJ_ERR_IMPORT_HANDLER_NOT_DONE;
        if (!WaitForRuntime(runtime, symbol_state, import_state))
        {
            PrintRuntimeFailure(symbol_state, import_state);
            PauseBeforeExit();
            return 1;
        }
        wprintf(L"%ls[+]%ls Download completed.\n\n", kGreen, kReset);

        TargetSelection target;
        bool cancelled = false;
        if (!SelectTarget(config.target_name, target, cancelled))
        {
            if (cancelled)
            {
                wprintf(L"Cancelled.\n");
                return 0;
            }
            return 2;
        }

        if (target.architecture == Architecture::X86)
        {
            PrintError(L"x86 targets are not supported in this x64-only build.");
            PauseBeforeExit();
            return 1;
        }

        // Deferred architecture cross-check (SelectDll could not do it without
        // a target). Matches the old interactive behavior: warn + confirm.
        if (target.architecture != Architecture::Unknown &&
            fileInformation.architecture != target.architecture)
        {
            wprintf(L"Warning: DLL is %ls but target is %ls.\n",
                ArchitectureName(fileInformation.architecture),
                ArchitectureName(target.architecture));
            bool proceed = false;
            if (!ReadYesNo(L"Continue anyway?", false, proceed) || !proceed)
            {
                wprintf(L"Cancelled.\n");
                return 0;
            }
        }

        // Note: late boot only warns (see SelectTarget). A hard refuse here
        // would have blocked your 25s success: late DllMain is probabilistic
        // (thread/state lottery), not guaranteed failure, so never abort on
        // age alone.

        const int timeout_value = config.timeout;

        wprintf(L"\n");

        if (!RefreshTarget(target))
        {
            PrintError(L"Target exited before loading. Re-run and choose faster.");
            PauseBeforeExit();
            return 1;
        }

        if (target.architecture == Architecture::X86)
        {
            PrintError(L"x86 targets are not supported in this x64-only build.");
            PauseBeforeExit();
            return 1;
        }

        // Sponsor handle: pre-open the target while INJ_HANDLE_HIJACKING is
        // set. The runtime DLL runs in-process, so it reuses this value
        // directly - validated first - with zero enumeration noise. The
        // optional roundtrip proof is controlled separately by
        // INJ_SKIP_SPONSOR_ROUNDTRIP; turning that off does not require
        // discarding the pre-opened handle. The guard keeps it alive through
        // the injection call below. Facts go into HijackContext for the
        // acquisition trace's first step.
        HijackContext Context{};
        Context.TargetPid = target.pid;
        Context.TargetName = target.name;
        Context.Verbose = config.verbose_trace && !config.quiet;
        Context.SponsorAccess = PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE |
            PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_DUP_HANDLE;
        HANDLE sponsorRaw = nullptr;
        if (config.handle_hijacking)
        {
            // Least privilege first: most targets open without it, and an
            // enabled SeDebugPrivilege is token state a process enumerator
            // can observe. Enable only when the open is denied for access.
            sponsorRaw = OpenProcess(Context.SponsorAccess, FALSE, target.pid);
            if (!sponsorRaw && GetLastError() == ERROR_ACCESS_DENIED)
            {
                Context.PrivilegeAttempted = true;
                Context.PrivilegeOk = EnableSeDebugPrivilege();
                if (Context.PrivilegeOk)
                {
                    sponsorRaw = OpenProcess(Context.SponsorAccess, FALSE, target.pid);
                }
                // Revoke immediately: the privilege is only needed for this one
                // open, and leaving it enabled is a lasting, enumerable trace on
                // our own token.
                DisableSeDebugPrivilege();
            }
            DWORD sponsor_err = ERROR_SUCCESS;
            if (!sponsorRaw)
            {
                sponsor_err = GetLastError();
            }
            Context.SponsorOpened = sponsorRaw != nullptr;
            if (sponsorRaw)
            {
                Context.SponsorValue = ReCa<ULONG_PTR>(sponsorRaw);
            }
            else
            {
                const wchar_t * consequence = config.hijack_scan
                    ? L"runtime will scan only (no direct fallback)."
                    : L"no acquisition path remains; loading will fail closed.";
                wprintf(L"  %ls[!]%ls Sponsor pre-open failed (0x%08X); %ls\n",
                    kYellow, kReset, sponsor_err, consequence);
            }
        }
        FileHandleGuard sponsorGuard(sponsorRaw);

        // Sponsor thread: pre-pick the victim thread and pre-open it, so the
        // runtime can duplicate it directly instead of scanning. Keep it
        // enabled even when the process roundtrip proof is disabled; the
        // remote alloc/write/read/free proof is separate from handle reuse.
        //
        // The pick is a snapshot (NtQuerySystemInformation), so the chosen TID
        // can exit before OpenThread runs. OpenThread then fails with
        // ERROR_INVALID_PARAMETER (0x57) on a dead TID - common on a
        // long-running, thread-churning target - and the runtime loses its
        // sponsor fast path. Retry with a fresh snapshot so that race does not
        // cost the stealthy path. The retry is bounded and only runs after a
        // failed open, so the steady state still issues exactly one pick and
        // one open.
        HANDLE threadSponsorRaw = nullptr;
        if (config.handle_hijacking)
        {
            Context.SponsorThreadAttempted = true;
            DWORD thread_sponsor_err = ERROR_SUCCESS;
            for (int attempt = 0; attempt < 8 && !threadSponsorRaw; ++attempt)
            {
                if (attempt > 0)
                {
                    Sleep(20);
                }

                const DWORD victim_tid = PickHijackThreadTid(target.pid);
                if (!victim_tid)
                {
                    // No candidate in the snapshot at all. This is not an
                    // OpenThread failure, so never surface a stale
                    // GetLastError() here (a pick miss used to print as 0x57).
                    thread_sponsor_err = ERROR_NOT_FOUND;
                    continue;
                }

                threadSponsorRaw = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT |
                    THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION,
                    FALSE, victim_tid);
                if (!threadSponsorRaw)
                {
                    thread_sponsor_err = GetLastError();
                }
            }

            if (threadSponsorRaw)
            {
                Context.SponsorThreadOpened = true;
                Context.SponsorThreadValue = ReCa<ULONG_PTR>(threadSponsorRaw);
                Context.SponsorTid = GetThreadId(threadSponsorRaw);
            }
            else
            {
                wprintf(L"  %ls[!]%ls Thread sponsor pre-open failed (0x%08X); runtime will search.\n",
                    kYellow, kReset, thread_sponsor_err);
            }
        }
        FileHandleGuard threadSponsorGuard(threadSponsorRaw);

        // One handle serves the pre/post hook scan and the post-injection
        // stealth report. The sponsor pre-open already carries
        // VM_OPERATION|VM_READ|VM_WRITE|QUERY, so the common path issues no
        // extra OpenProcess (the loudest telemetry point). Only when the
        // sponsor is absent do we open a scan-only handle once, here.
        HANDLE targetHandle = sponsorRaw;
        FileHandleGuard targetHandleGuard;
        if (!targetHandle)
        {
            // Verification/survey reads need QUERY + VM_READ only. WRITE and
            // OPERATION exist solely for the hook-restore writes, so they are
            // requested only when HookRestore can actually write; otherwise
            // this fallback handle carries the quietest usable mask.
            DWORD scan_mask = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ;
            if (config.hook_restore && HookPatchExplicitlyAllowed())
            {
                scan_mask |= PROCESS_VM_WRITE | PROCESS_VM_OPERATION;
            }
            targetHandle = OpenProcess(scan_mask, FALSE, target.pid);
            targetHandleGuard.reset(targetHandle);
            if (!targetHandle)
            {
                wprintf(L"  %ls[!]%ls Could not open the target for hook scanning (0x%08X).\n",
                    kYellow, kReset, GetLastError());
            }
        }

        const DWORD flags = BuildFlags(config);

        MemoryInjectionData data{};
        data.RawData = raw_data.data();
        data.RawSize = static_cast<DWORD>(raw_data.size());
        data.ProcessID = target.pid;
        data.Mode = INJECTION_MODE::IM_ManualMap;
        data.Method = LAUNCH_METHOD::LM_HijackThread;
        data.Flags = flags;
        data.Timeout = static_cast<DWORD>(timeout_value);
        data.GenerateErrorLog = true;
        // Kernel handle values fit in 32 bits; the runtime widens back.
        data.hHandleValue = sponsorRaw ? ReCa<ULONG_PTR>(sponsorRaw) : 0;
        data.TargetTid = Context.SponsorTid;
        data.hThreadHandleValue = threadSponsorRaw ? ReCa<ULONG_PTR>(threadSponsorRaw) : 0;

        wprintf(L"\n");
        // Pre-injection hook scan: system DLLs only (guard-aware, see
        // IsSafeCodePage). Game .text/.eid traps are surveyed once,
        // read-only, as the last verification step after injection — never
        // written: Warden's INT3 trampolines, page-guarded .eid dispatch,
        // VEH-first chain and session-rotated IAT keys have no safe static
        // restore. This pre-scan only writes system code pages, so turn it
        // off with HookRestore = N.
        if (config.hook_restore)
        {
            std::vector<RestoredHook> pre_unhooked;
            std::vector<std::wstring> pre_remaining;
            HookScanStats pre_stats{};
            ScanAndRestoreHooks(targetHandle, pre_unhooked, pre_remaining, pre_stats);
            if (!config.quiet)
            {
                PrintHookScanResult(L"Pre-load hook", pre_stats, pre_unhooked, pre_remaining);
            }
        }

        // A single attempt, always. The failure path deliberately does not
        // retry in-process: a retry would be a second exposure into a target
        // whose DllMain already ran and refused, and it leaves loader
        // bookkeeping that ntdll offers no API to reclaim - the
        // inverted-function-table entry (and the fake SEH directory it
        // may reference) and the LdrpHandleTlsData TLS index/block both point
        // into the freed image and dangle for the life of the target. Releasing
        // the TLS index would let a later TlsAlloc hand every thread a stale
        // pointer. Fail instead, and have the operator relaunch the target
        // before re-running.
        //
        // The progress line is printed before memory_inject because it blocks
        // for the whole timeout when the payload hangs, so name the victim
        // thread and the wait budget before the silence starts. Flush left;
        // the measured TID and timeout are tinted green.
        // This TID is the sponsor thread that was REQUESTED, not necessarily the
        // one that ends up hijacked: the runtime re-validates it (a parked
        // non-alertable waiter or loader worker cannot be woken and is
        // rejected) and the donor scan may then select a different thread
        // entirely. Printing it as "the" working thread is what previously made
        // a successful run look inconsistent, because the authoritative
        // hijacked TID is only known once telemetry reports it at the end. The
        // hijack may also resume the requested thread untouched if no donor is
        // found.
        if (data.TargetTid)
        {
            wprintf(L"Requested sponsor TID %ls0x%04lX%s, Timeout %ls%lu ms%s (runtime may reject it; hijacked thread reported on completion)...\n",
                kGreen, static_cast<unsigned long>(data.TargetTid), kReset,
                kGreen, static_cast<unsigned long>(data.Timeout), kReset);
        }
        else
        {
            wprintf(L"Working (runtime thread search, timeout %ls%lu ms%s)...\n",
                kGreen, static_cast<unsigned long>(data.Timeout), kReset);
        }

        const DWORD result = runtime.memory_inject(&data);

        if (result != INJ_ERR_SUCCESS)
        {
            fwprintf(stderr, L"%lsOperation failed with code %08X%ls\n", kRed, result, kReset);
            PrintFailureHint(result);
            // Any failure at or after the remote shell started leaves loader
            // bookkeeping in the target that ntdll offers no way to reclaim
            // (inverted-function-table entry, TLS index/block and the loader
            // lock cookie all point into the freed image or stay held). Say so
            // explicitly: retrying into the same process is not safe.
            if (result >= 0x00400000u)
            {
                wprintf(L"  %ls[!]%ls Remote mapping reached the shell; unreclaimable loader state may remain.\n",
                    kYellow, kReset);
                wprintf(L"      Relaunch the target before attempting another load.\n");
            }
            targetHandleGuard.reset();
            threadSponsorGuard.reset();
            sponsorGuard.reset();
            PauseBeforeExit();
            return 1;
        }

        // Release the CONTEXT-capable thread handle immediately now that the
        // runtime holds its own duplicate. OpenThread itself is not observable
        // from the target (no notification is sent on handle creation), but a
        // system-wide handle enumeration shows an external process holding
        // SUSPEND_RESUME|GET/SET_CONTEXT on one of the game's threads - the
        // exact capability a context hijack needs, and far more incriminating
        // than a query-only handle. Nothing after this point uses it: the
        // verification steps read target memory through the process handle.
        threadSponsorGuard.reset();
        threadSponsorRaw = nullptr;

        // Retire the write-capable process handle too, when nothing needs it.
        // VM_WRITE|VM_OPERATION held by an outside process is the single most
        // incriminating artifact in this design - it literally means "another
        // process can write my memory" - so it is kept strictly to the window
        // where the mapping actually happens. Verification and the trap survey
        // only READ target memory, and the hook restore (the sole writer) is
        // disabled in the stealth configuration, so a query+read handle is
        // sufficient afterwards. Cost: one extra OpenProcess, which is not
        // observable as a call; benefit: the strong handle stops existing.
        if (sponsorRaw && !config.hook_restore)
        {
            sponsorGuard.reset();
            sponsorRaw = nullptr;
            targetHandle = nullptr;

            targetHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, target.pid);
            targetHandleGuard.reset(targetHandle);
            if (!targetHandle)
            {
                wprintf(L"  %ls[!]%ls Could not re-open the target read-only for verification (0x%08X).\n",
                    kYellow, kReset, GetLastError());
            }
        }

        // Debug and verify stealth results in the remote process (pipeline runs
        // inside the remote process, so we can only display results after injection).
        // The runtime records its real handle-acquisition outcome per kind;
        // fetch it for the first step instead of guessing from static text.
        // The game-trap survey always runs last (read-only, one line per
        // module) so the step count already includes it.
        HijackStats ProcessHijackStats{};
        HijackStats ThreadHijackStats{};
        if (runtime.get_last_hijack_stats)
        {
            runtime.get_last_hijack_stats(&ProcessHijackStats, &ThreadHijackStats);
        }
        MAP_STATS MapStats{};
        if (runtime.get_last_map_stats)
        {
            runtime.get_last_map_stats(&MapStats);
        }

        // Thread-hijack outcome, measured in the target. Fetched BEFORE the
        // acquisition trace is printed (SafeDebugAndVerifyStealth below) so the
        // trace can name the TID that was actually hijacked and flag a
        // sponsor-vs-used mismatch. This used to be a fixed "Thread context
        // restored automatically" string with nothing behind it; the
        // measurement is real: the runtime watches RIP until it leaves the
        // hijack code page before reporting the restore.
        THREAD_EXEC_STATS ThreadExec{};
        if (runtime.get_last_thread_exec_stats)
        {
            runtime.get_last_thread_exec_stats(&ThreadExec);
        }
        Context.UsedTid = ThreadExec.HijackedTid;

        // Fail closed. If the handle is gone we cannot prove the stealth
        // properties, and every other unproven path in this gate (a missing
        // export, a fault inside verification) already reports failure. This
        // one used to default to true and skip the check entirely.
        bool stealth_gate_ok = false;
        bool wx_violated = false;
        if (targetHandle)
        {
            stealth_gate_ok = SafeDebugAndVerifyStealth(targetHandle, data.hDllOut, flags, raw_data.data(), raw_data.size(),
                &ProcessHijackStats, &ThreadHijackStats, &Context, &MapStats, runtime.get_last_string_stats, true, target.pid, &wx_violated);
        }
        else
        {
            wprintf(L"%ls[x]%ls Verification could not run (no target handle); the result is unproven.\n",
                kRed, kReset);
        }

        // ThreadExec was fetched above (before the acquisition trace) so the
        // trace could name the hijacked TID; report the measured restore here.
        if (!runtime.get_last_thread_exec_stats || !ThreadExec.Attempted)
        {
            wprintf(L"  %ls[!]%ls Thread context not reported (no telemetry, or no donor was attempted).\n", kYellow, kReset);
        }
        else if (ThreadExec.Success)
        {
            wprintf(L"  %ls[+]%ls Thread context restored to original on TID: %ls0x%04lX%s.\n",
                kGreen, kReset, kGreen, static_cast<unsigned long>(ThreadExec.HijackedTid), kReset);
        }
        else
        {
            wprintf(L"  %ls[!]%ls Thread context %sNOT restored%s on TID: %s0x%04lX%s (code 0x%08lX) - it may still be running donor code.\n",
                kYellow, kReset, kYellow, kReset, kYellow,
                static_cast<unsigned long>(ThreadExec.HijackedTid), kReset,
                static_cast<unsigned long>(ThreadExec.FailCode));
        }

        // Data-driven sponsor fallback disclosure, independent of VerboseTrace
        // (the detailed trace line only prints in verbose mode). A pre-opened
        // sponsor TID is a hint: the runtime re-validates it and may select a
        // different thread via the donor scan. Naming both TIDs here keeps a
        // legitimate fallback from reading as an inconsistency.
        if (ThreadExec.Attempted && data.TargetTid && ThreadExec.HijackedTid
            && ThreadExec.HijackedTid != data.TargetTid)
        {
            wprintf(L"  %ls[!]%ls Sponsor TID %ls0x%04lX%ls not usable; hijacked TID %ls0x%04lX%ls instead (donor scan fallback).\n",
                kYellow, kReset,
                kGreen, static_cast<unsigned long>(data.TargetTid), kReset,
                kGreen, static_cast<unsigned long>(ThreadExec.HijackedTid), kReset);
        }
        wprintf(L"\n");
        if (config.hook_restore)
        {
            std::vector<RestoredHook> unhooked;
            std::vector<std::wstring> remaining;
            HookScanStats post_stats{};
            ScanAndRestoreHooks(targetHandle, unhooked, remaining, post_stats);
            if (!config.quiet)
            {
                PrintHookScanResult(L"Post-load hook", post_stats, unhooked, remaining);
            }
        }

        // Drop every open handle into the target the moment verification no
        // longer needs them: VM_WRITE-class handles held by an outside
        // process are the loudest handle-enumeration signal, and everything
        // below works off already-collected results. The runtime duplicated
        // what it needed during CoreExecute, so closing here changes nothing
        // functionally. Guards close their handles; raw locals are nulled so
        // no later path can reuse them.
        // 
        targetHandleGuard.reset();
        threadSponsorGuard.reset();
        sponsorGuard.reset();
        const bool had_target = (targetHandle != nullptr);
        targetHandle = nullptr;
        threadSponsorRaw = nullptr;
        sponsorRaw = nullptr;

        wprintf(L"\n");
        if (!stealth_gate_ok)
        {
            if (!had_target)
            {
                // Verification was skipped entirely (no handle to inspect), so
                // blaming string encryption would be a lie: nothing was proven
                // either way. Report it as unproven, not as a leak.
                wprintf(L"%ls[x] VERIFICATION NOT PERFORMED%s - the payload is mapped in the\n", kRed, kReset);
                wprintf(L"    target, but no target handle was available, so neither the string-encryption\n");
                wprintf(L"    gate nor the W^X posture could be checked. The result is unproven; do not\n");
                wprintf(L"    treat it as a clean load until it can be verified.\n");
            }
            else
            {
                wprintf(L"%ls[x] VERIFICATION GATE FAILED%s - the payload is mapped in the target, but the\n", kRed, kReset);
                wprintf(L"    runtime DLL does not pass verification (string-encryption or forensic posture).\n");
                wprintf(L"    It must not be treated as a clean load: a plaintext symbol name in .rdata is\n");
                wprintf(L"    scannable, and shipping it defeats the point of the string tiers.\n");
                wprintf(L"    Fix the leak and rebuild before using this build.\n");
            }
            PauseBeforeExit();
            return 1;
        }
        if (wx_violated)
        {
            wprintf(L"%ls[!] W^X advisory:%s the W^X posture was not confirmed (see the Verify W^X execution step).\n", kYellow, kReset);
            wprintf(L"    Either a mapped page is not RX as expected, or the image could not be queried\n");
            wprintf(L"    or bounded. The load is functional, but this weakens confidence in the\n");
            wprintf(L"    W^X posture. Treat this build as suspect.\n\n");
        }

        wprintf(L"Operation succeeded. DLL loaded at %ls%p%s.\n", kGreen, data.hDllOut, kReset);
        PauseBeforeExit();
        return 0;
    }
}

// Interface entry point.
int wmain()
{
    EnableAnsi();
    Runtime runtime;
    int result = 1;
    try
    {
        result = RunInteractiveWizard(runtime);
    }
    catch (const std::bad_alloc &)
    {
        PrintError(L"Out of memory during loading; aborting.");
        PauseBeforeExit();
        result = 1;
    }
    if (runtime.module)
    {
        // Graceful shutdown: stop symbol/import workers and release PDB
        // handles before killing the process. Previously TerminateProcess
        // ran unconditionally, leaking the symbol thread + DbgHelp session
        // whenever the wizard exited early (0x4E path included). Best-effort:
        // a wedged worker must not hang the exit.
        if (runtime.shutdown_runtime)
        {
            runtime.shutdown_runtime();
        }
        TerminateInterface(result);
    }
    return result;
}
