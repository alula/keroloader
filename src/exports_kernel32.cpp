#include <cstdint>
#include <ctime>
#include <cstring>
#include <string>
#include <unordered_map>
#include "common.h"
#include "exports.h"

typedef struct _STARTUPINFOW
{
    DWORD cb;
    LPWSTR lpReserved;
    LPWSTR lpDesktop;
    LPWSTR lpTitle;
    DWORD dwX;
    DWORD dwY;
    DWORD dwXSize;
    DWORD dwYSize;
    DWORD dwXCountChars;
    DWORD dwYCountChars;
    DWORD dwFillAttribute;
    DWORD dwFlags;
    WORD wShowWindow;
    WORD cbReserved2;
    LPBYTE lpReserved2;
    HANDLE hStdInput;
    HANDLE hStdOutput;
    HANDLE hStdError;
} STARTUPINFOW, *LPSTARTUPINFOW;

typedef struct _OSVERSIONINFOEXW
{
    DWORD dwOSVersionInfoSize;
    DWORD dwMajorVersion;
    DWORD dwMinorVersion;
    DWORD dwBuildNumber;
    DWORD dwPlatformId;
    WCHAR szCSDVersion[128];
    WORD wServicePackMajor;
    WORD wServicePackMinor;
    WORD wSuiteMask;
    BYTE wProductType;
    BYTE wReserved;
} OSVERSIONINFOEXW, *POSVERSIONINFOEXW, *LPOSVERSIONINFOEXW, RTL_OSVERSIONINFOEXW, *PRTL_OSVERSIONINFOEXW;

static OSVERSIONINFOEXW system_ver_info_wide = {
    .dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW),
    .dwMajorVersion = 6,
    .dwMinorVersion = 2,
    .dwBuildNumber = 21370,
    .dwPlatformId = 0,
    .szCSDVersion = {0},
    .wServicePackMajor = 0,
    .wServicePackMinor = 0,
    .wSuiteMask = 0x200,
    .wProductType = 1,
    .wReserved = 0};

struct kernel32_env_t
{
    char16_t idk[256] = u"";
};

constexpr int64_t ftime_offset = 0x2b6109100LL;
constexpr int64_t ftime_second = 10000000LL;

uint32_t kern32_env_base = 0xf0008000;
uint32_t kern32_env_size = 0;
uint32_t curr_process_handle = 0x1000;
uint32_t curr_module_handle = 0x1001;
uint32_t curr_heap_handle = 0x1002;
uint32_t curr_pid = 2137;
uint32_t seh_handler = 0;

uint32_t heaps_start = 0x20000000;
uint32_t heaps_end = 0x80000000;

// {slot -> {thread_id -> value}}
std::unordered_map<uint32_t, std::unordered_map<uint32_t, uint32_t>> fiber_storage;
// {slot -> fiber_cb}
std::unordered_map<uint32_t, uint32_t> fiber_callbacks;

// {critical section handle -> owning thread}
std::unordered_map<uint32_t, uint32_t> crit_sections;

static void cb_kernel32_InitializeCriticalSectionEx(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t lp_crit_section;
    uint32_t dw_spin_count;
    uint32_t flags;
    uint32_t ret = 0;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &lp_crit_section, 4));
    uc_assert(uc_mem_read(uc, esp + 8, &dw_spin_count, 4));
    uc_assert(uc_mem_read(uc, esp + 12, &flags, 4));

    if (lp_crit_section != 0)
    {
        crit_sections[lp_crit_section] = 0;
        ret = 1;
    }

    esp += 16;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_kernel32_EnterCriticalSection(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t lp_crit_section;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &lp_crit_section, 4));

    // no op till we get threading

    esp += 8;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_kernel32_FlsAlloc(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t callback;
    uint32_t ret = 0xffffffff;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &callback, 4));

    for (uint32_t i = 0; i < 0xffff; i++)
    {
        if (fiber_storage.find(i) != fiber_storage.end())
        {
            ret = i;
            fiber_storage[i] = std::unordered_map<uint32_t, uint32_t>();

            if (callback != 0)
            {
                fiber_callbacks[i] = callback;
            }

            break;
        }
    }
    // todo lasterror

    esp += 8;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_kernel32_FlsSetValue(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t slot;
    uint32_t data;
    uint32_t ret = 0;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &slot, 4));
    uc_assert(uc_mem_read(uc, esp + 8, &data, 4));

    auto store = fiber_storage.find(slot);
    if (store != fiber_storage.end())
    {
        store->second[curr_thread] = data;
        ret = 1;
        // todo lasterror
    }

    esp += 12;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_kernel32_FlsGetValue(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t slot;
    uint32_t ret = 0;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &slot, 4));

    auto store = fiber_storage.find(slot);
    if (store != fiber_storage.end())
    {
        auto val = store->second.find(curr_thread);
        if (val != store->second.end())
        {
            ret = val->second;
        }
        // todo lasterror
    }

    esp += 12;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_kernel32_HeapCreate(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t fl_options;
    uint32_t initial_size;
    uint32_t max_size;
    uint32_t ret = 0;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &fl_options, 4));
    uc_assert(uc_mem_read(uc, esp + 8, &initial_size, 4));
    uc_assert(uc_mem_read(uc, esp + 12, &max_size, 4));

    // no need to handle that for now
    ret = curr_heap_handle;

    esp += 16;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_kernel32_GetVersionExW(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t version_tgt;
    uint32_t ret = 0;
    uint32_t size;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &version_tgt, 4));

    if (version_tgt != 0)
    {
        uc_assert(uc_mem_read(uc, version_tgt, &size, 4));
        uint32_t len = std::max((uint32_t)4, std::min(size, (uint32_t)sizeof(OSVERSIONINFOEXW))) - 4;
        uc_assert(uc_mem_write(uc, version_tgt + 4, &system_ver_info_wide.dwMajorVersion, len));

        ret = 1;
    }

    esp += 8;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_kernel32_GetCurrentProcessId(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    esp += 4;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &curr_pid));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_kernel32_GetCurrentProcess(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    esp += 4;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &curr_process_handle));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_kernel32_GetModuleHandleW(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t name_addr;
    uint32_t ret = 0;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &name_addr, 4));
    esp += 8;

    if (name_addr == 0)
    {
        ret = curr_module_handle;
    } else {
        auto mod_name = read_u16string(uc, name_addr);
    }

    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_kernel32_GetCurrentThreadId(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    esp += 4;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &curr_thread));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_kernel32_QueryPerformanceCounter(uc_engine *uc, uint32_t esp)
{
    struct timespec time_now;
    uint64_t time_value = 0;
    uint32_t time_ptr = 0;
    uint32_t time_tmp;
    uint32_t return_addr;

    //uc_assert(uc_reg_read(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &time_ptr, 4));
    esp += 8;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));

    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &time_now);
    time_value = time_now.tv_sec * 1000000000 + time_now.tv_nsec;

    time_tmp = (uint32_t)time_value;
    uc_assert(uc_mem_write(uc, time_ptr, &time_tmp, 4));
    time_tmp = (uint32_t)(time_value >> 32);
    uc_assert(uc_mem_write(uc, time_ptr + 4, &time_tmp, 4));
    time_tmp = 1;
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &time_tmp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_kernel32_GetTickCount(uc_engine *uc, uint32_t esp)
{
    struct timespec time_now;
    uint32_t time_value;
    uint32_t return_addr;

    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    esp += 4;

    clock_gettime(CLOCK_MONOTONIC, &time_now);
    time_value = time_now.tv_sec * 1000 + (time_now.tv_nsec / 1000000);

    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &time_now));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_kernel32_GetSystemTimeAsFileTime(uc_engine *uc, uint32_t esp)
{
    struct timeval time_now;
    uint64_t time_value = 0;
    uint32_t time_ptr = 0;
    uint32_t time_tmp;
    uint32_t return_addr;

    //uc_assert(uc_reg_read(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &time_ptr, 4));
    esp += 8;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));

    gettimeofday(&time_now, 0);
    time_value = (time_now.tv_sec + ftime_offset) * ftime_second;
    time_value += time_now.tv_usec / 100LL;

    time_tmp = (uint32_t)time_value;
    uc_assert(uc_mem_write(uc, time_ptr, &time_tmp, 4));
    time_tmp = (uint32_t)(time_value >> 32);
    uc_assert(uc_mem_write(uc, time_ptr + 4, &time_tmp, 4));

    //logf("NtQuerySystemTime(%#010x) -> %ld\n", time_ptr, time_value);
    //logf("ret to %#010x\n", return_addr);

    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_kernel32_GetStartupInfoW(uc_engine *uc, uint32_t esp)
{
    STARTUPINFOW startup_info;
    uint32_t startup_info_ptr;
    uint32_t return_addr;

    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &startup_info_ptr, 4));
    esp += 8;

    memset(&startup_info, 0, sizeof(STARTUPINFOW));
    startup_info.hStdOutput = 0x800;
    startup_info.hStdInput = 0x801;
    startup_info.hStdError = 0x802;

    uc_mem_write(uc, startup_info_ptr, &startup_info, sizeof(STARTUPINFOW));

    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_kernel32_HeapSetInformation(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t ret = 1;

    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    // heap_handle = [esp + 4]
    // heap_info_class = [esp + 8]
    // heap_info = [esp + 12]
    // heap_info_length = [esp + 16]
    esp += 20;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

// doesn't have to be synchronized since entire emulator is single-threaded.
static void cb_kernel32_InterlockedCompareExchange(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t dest_addr;
    uint32_t exchange;
    uint32_t comperand;
    uint32_t og_value;

    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &dest_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 8, &exchange, 4));
    uc_assert(uc_mem_read(uc, esp + 12, &comperand, 4));
    esp += 16;

    uc_assert(uc_mem_read(uc, dest_addr, &og_value, 4));
    if (og_value == comperand)
    {
        uc_assert(uc_mem_write(uc, dest_addr, &exchange, 4));
    }

    //printf("InterlockedCompareExchange(%#010x, %#010x, %#010x)\n", dest_addr, exchange, comperand);

    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &og_value));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_kernel32_InterlockedExchange(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t dest_addr;
    uint32_t exchange;
    uint32_t og_value;

    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &dest_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 8, &exchange, 4));
    esp += 12;

    uc_assert(uc_mem_read(uc, dest_addr, &og_value, 4));
    uc_assert(uc_mem_write(uc, dest_addr, &exchange, 4));

    //printf("InterlockedCompareExchange(%#010x, %#010x, %#010x)\n", dest_addr, exchange, comperand);

    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &og_value));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static uint32_t ptr_secret = 0;

static void cb_kernel32_EncodePointer(uc_engine *uc, uint32_t esp)
{
    uint32_t ptr_in;
    uint32_t return_addr;

    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &ptr_in, 4));
    esp += 8;

    ptr_in -= ptr_secret;

    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ptr_in));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_kernel32_DecodePointer(uc_engine *uc, uint32_t esp)
{
    uint32_t ptr_in;
    uint32_t return_addr;

    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &ptr_in, 4));
    esp += 8;

    ptr_in += ptr_secret;

    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ptr_in));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_kernel32_Sleep(uc_engine *uc, uint32_t esp)
{
    uint32_t time;
    uint32_t return_addr;

    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &time, 4));
    esp += 8;

    usleep(time * 1000);

    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &time));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_kernel32_IsProcessorFeaturePresent(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t ret = 0;

    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    // feature = [esp + 4]
    esp += 8;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_kernel32_SetUnhandledExceptionFilter(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t addr = 0;

    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &addr, 4));

    // todo bind to thread?
    seh_handler = addr;

    esp += 8;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_kernel32_OpenMutexW(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t desired_access;
    bool inherit_handle;
    uint32_t name;
    uint32_t ret = 0;

    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &desired_access, 4));
    uc_assert(uc_mem_read(uc, esp + 8, &inherit_handle, 1));
    uc_assert(uc_mem_read(uc, esp + 12, &name, 4));

    esp += 16;

    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_kernel32_CreateFileMappingW(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t handle;
    uint32_t map_attributes;
    uint32_t fl_protect;
    uint32_t max_size_hi;
    uint32_t max_size_lo;
    uint32_t name;
    uint32_t ret = 0;

    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &handle, 4));
    uc_assert(uc_mem_read(uc, esp + 8, &map_attributes, 1));
    uc_assert(uc_mem_read(uc, esp + 12, &fl_protect, 1));
    uc_assert(uc_mem_read(uc, esp + 16, &max_size_hi, 1));
    uc_assert(uc_mem_read(uc, esp + 20, &max_size_lo, 1));
    uc_assert(uc_mem_read(uc, esp + 24, &name, 4));

    esp += 28;

    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_kernel32_SetPriorityClass(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t process_handle;
    uint32_t priority;
    uint32_t ret = 0;

    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &process_handle, 4));
    uc_assert(uc_mem_read(uc, esp + 8, &priority, 1));

    esp += 12;

    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

void install_kernel32_exports(uc_engine *uc)
{
    {
        kernel32_env_t ke;
        memset(&ke, 0, sizeof(STARTUPINFOW));

        kern32_env_size = align_address(sizeof(kernel32_env_t));
        uc_assert(uc_mem_map(uc, kern32_env_base, kern32_env_size, UC_PROT_READ | UC_PROT_WRITE));
    }

    ptr_secret = random() ^ random() ^ random() - 0xf35d7c1a;

    Export FlsAlloc_ex = {"FlsAlloc", cb_kernel32_FlsAlloc};
    exports["FlsAlloc"] = FlsAlloc_ex;

    Export FlsSetValue_ex = {"FlsSetValue", cb_kernel32_FlsSetValue};
    exports["FlsSetValue"] = FlsSetValue_ex;

    Export FlsGetValue_ex = {"FlsGetValue", cb_kernel32_FlsGetValue};
    exports["FlsGetValue"] = FlsGetValue_ex;

    Export HeapCreate_ex = {"HeapCreate", cb_kernel32_HeapCreate};
    exports["HeapCreate"] = HeapCreate_ex;

    Export GetVersionExW_ex = {"GetVersionExW", cb_kernel32_GetVersionExW};
    exports["GetVersionExW"] = GetVersionExW_ex;

    Export NtQuerySystemTime_ex = {"NtQuerySystemTime", cb_kernel32_GetSystemTimeAsFileTime};
    exports["NtQuerySystemTime"] = NtQuerySystemTime_ex;

    Export GetSystemTimeAsFileTime_ex = {"GetSystemTimeAsFileTime", cb_kernel32_GetSystemTimeAsFileTime};
    exports["GetSystemTimeAsFileTime"] = GetSystemTimeAsFileTime_ex;

    Export GetCurrentProcessId_ex = {"GetCurrentProcessId", cb_kernel32_GetCurrentProcessId};
    exports["GetCurrentProcessId"] = GetCurrentProcessId_ex;

    Export GetCurrentProcess_ex = {"GetCurrentProcess", cb_kernel32_GetCurrentProcess};
    exports["GetCurrentProcess"] = GetCurrentProcess_ex;

    Export GetModuleHandleW_ex = {"GetModuleHandleW", cb_kernel32_GetModuleHandleW};
    exports["GetModuleHandleW"] = GetModuleHandleW_ex;

    Export GetCurrentThreadId_ex = {"GetCurrentThreadId", cb_kernel32_GetCurrentThreadId};
    exports["GetCurrentThreadId"] = GetCurrentThreadId_ex;

    Export QueryPerformanceCounter_ex = {"QueryPerformanceCounter", cb_kernel32_QueryPerformanceCounter};
    exports["QueryPerformanceCounter"] = QueryPerformanceCounter_ex;

    Export GetTickCount_ex = {"GetTickCount", cb_kernel32_GetTickCount};
    exports["GetTickCount"] = GetTickCount_ex;

    Export GetStartupInfoW_ex = {"GetStartupInfoW", cb_kernel32_GetStartupInfoW};
    exports["GetStartupInfoW"] = GetStartupInfoW_ex;

    Export HeapSetInformation_ex = {"HeapSetInformation", cb_kernel32_HeapSetInformation};
    exports["HeapSetInformation"] = HeapSetInformation_ex;

    Export InterlockedCompareExchange_ex = {"InterlockedCompareExchange", cb_kernel32_InterlockedCompareExchange};
    exports["InterlockedCompareExchange"] = InterlockedCompareExchange_ex;

    Export InterlockedExchange_ex = {"InterlockedExchange", cb_kernel32_InterlockedExchange};
    exports["InterlockedExchange"] = InterlockedExchange_ex;

    Export EncodePointer_ex = {"EncodePointer", cb_kernel32_EncodePointer};
    exports["EncodePointer"] = EncodePointer_ex;

    Export DecodePointer_ex = {"DecodePointer", cb_kernel32_DecodePointer};
    exports["DecodePointer"] = DecodePointer_ex;

    Export IsProcessorFeaturePresent_ex = {"IsProcessorFeaturePresent", cb_kernel32_IsProcessorFeaturePresent};
    exports["IsProcessorFeaturePresent"] = IsProcessorFeaturePresent_ex;

    Export SetUnhandledExceptionFilter_ex = {"SetUnhandledExceptionFilter", cb_kernel32_SetUnhandledExceptionFilter};
    exports["SetUnhandledExceptionFilter"] = SetUnhandledExceptionFilter_ex;

    Export OpenMutexW_ex = {"OpenMutexW", cb_kernel32_OpenMutexW};
    exports["OpenMutexW"] = OpenMutexW_ex;

    Export CreateFileMappingW_ex = {"CreateFileMappingW", cb_kernel32_CreateFileMappingW};
    exports["CreateFileMappingW"] = CreateFileMappingW_ex;

    Export Sleep_ex = {"Sleep", cb_kernel32_Sleep};
    exports["Sleep"] = Sleep_ex;

    Export SetPriorityClass_ex = {"SetPriorityClass", cb_kernel32_SetPriorityClass};
    exports["SetPriorityClass"] = SetPriorityClass_ex;
}