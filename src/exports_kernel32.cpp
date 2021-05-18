#include <cstdint>
#include <ctime>
#include <cstring>
#include <cwctype>
#include <string>
#include <unordered_map>
#include <filesystem>
#include <iostream>
#include <fnmatch.h>
#include "common.h"
#include "exports.h"
#include "tinyalloc/tinyalloc.h"
#include "windows/winerror.h"

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

static std::u16string program_path = u".\\KeroBlaster.exe";

struct kernel32_env_t
{
    // doesn't matter for KB
    char16_t environment_variables_wide[1024 * 32] = u"PATH=C:\\Windows\\system32\0WINDIR=C:\\Windows\0USERPROFILE=C:\\Users\\keroloader";
    char16_t cmdline_wide[1024 * 32] = u"\".\\KeroBlaster.exe\"";
    char cmdline_ascii[1024 * 32] = "\".\\KeroBlaster.exe\"";
};

constexpr int64_t ftime_offset = 0x2b6109100LL;
constexpr int64_t ftime_second = 10000000LL;

uint32_t kern32_env_base = 0xf0008000;
uint32_t kern32_env_size = 0;
uint32_t curr_process_handle = 0x1000;
uint32_t curr_module_handle = 0x1001;
uint32_t curr_heap_handle = 0x1002;
uint32_t user32_handle = 0x1003;
uint32_t kernel32_handle = 0x1004;
uint32_t gdi32_handle = 0x1005;
uint32_t winmm_handle = 0x1006;
uint32_t msvcrt_handle = 0x1007;
uint32_t msvcr100_handle = 0x1008;
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

struct FindFileData
{
    std::filesystem::directory_iterator iter;
    std::string pattern;
    uint32_t flags = 0;

    bool next_wide(uc_engine *uc, uint32_t find_file_data_w_addr)
    {
        int fnflags = FNM_PATHNAME;
        if ((flags & 1) != 0)
            fnflags |= FNM_CASEFOLD;

        for (;;)
        {
            try
            {
                auto file = *iter;
                printf("%s %s -> ", pattern.c_str(), file.path().filename().c_str());
                std::error_code err;
                iter.increment(err);

                if (fnmatch(pattern.c_str(), file.path().filename().c_str(), fnflags) == 0)
                {
                    printf("matched!\n");
                    return true;
                }
                else
                {
                    printf("unmatched\n");
                }
            }
            catch (std::out_of_range)
            {
                break;
            }
        }
        return false;
    }
};

void set_last_error(std::error_code const &err)
{
    if (err == std::errc::file_exists)
    {
        last_error = ERROR_ALREADY_EXISTS;
    }
    else if (err == std::errc::no_such_file_or_directory)
    {
        last_error = ERROR_PATH_NOT_FOUND;
    }
    else
    {
        last_error = ERROR_ACCESS_DENIED;
    }
}

std::unordered_map<uint32_t, FindFileData> find_file_handles;

extern uint16_t gstw_ct1_table[0x10000];
extern uint16_t gstw_ct2_table[0x10000];
extern uint16_t gstw_ct3_table[0x10000];

static tinyalloc::HeapAllocator allocator;

static void cb_kernel32_FindFirstFileW(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t lp_filename;
    uint32_t lp_find_file_data;
    uint32_t ret = 0;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &lp_filename, 4));
    uc_assert(uc_mem_read(uc, esp + 8, &lp_find_file_data, 4));

    if (lp_filename != 0)
    {
        auto path = to_unix_path(read_u16string(uc, lp_filename));
        auto split = split_unix_path(path);
        FindFileData f;
        std::error_code err;
        f.iter = std::filesystem::directory_iterator(split.first, err);
        f.pattern = split.second;
        // f.flags = dw_additional_flags;

        printf("%s %s\n", path.c_str(), split.first.c_str(), split.second.c_str());

        if (!err)
        {
            for (uint32_t i = 0x9000; i < 0xffff; i++)
            {
                if (find_file_handles.find(i) == find_file_handles.end())
                {
                    if (f.next_wide(uc, lp_find_file_data))
                    {
                        ret = i;
                        find_file_handles[i] = f;
                    }
                    else
                    {
                        ret = 0;
                    }
                    break;
                }
            }
        }
        else
        {
            set_last_error(err);
            ret = 0;
        }
    }

    for(;;);
    esp += 12;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_kernel32_CreateDirectoryW(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t path_buf;
    uint32_t ret = 0;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &path_buf, 4));
    // ignore security attrib

    if (path_buf != 0)
    {
        const auto path = to_unix_path(read_u16string(uc, path_buf));

        std::error_code err;
        if (std::filesystem::create_directory(path, err))
        {
            ret = 1;
        }
        else
        {
            set_last_error(err);
            ret = 0;
        }
    }

    esp += 12;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_kernel32_GetModuleFileNameW(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t handle;
    uint32_t buf_ptr;
    uint32_t buf_size;
    uint32_t ret;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &handle, 4));
    uc_assert(uc_mem_read(uc, esp + 8, &buf_ptr, 4));
    uc_assert(uc_mem_read(uc, esp + 12, &buf_size, 4));

    if (handle != 0)
    {
        ret = 0;
        last_error = ERROR_INVALID_HANDLE;
    }
    else
    {
        if (buf_size != 0)
        {
            buf_size *= 2;
            uint32_t to_copy = program_path.size() * 2;
            if (to_copy > buf_size)
            {
                last_error = ERROR_INSUFFICIENT_BUFFER;
                to_copy = buf_size;
            }

            uc_assert(uc_mem_write(uc, buf_ptr, program_path.data(), to_copy));
            ret = to_copy;
        }
        else
        {
            last_error = ERROR_SUCCESS;
            ret = 0;
        }
    }

    esp += 16;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_kernel32_GetModuleFileNameA(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t handle;
    uint32_t buf_ptr;
    uint32_t buf_size;
    uint32_t ret;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &handle, 4));
    uc_assert(uc_mem_read(uc, esp + 8, &buf_ptr, 4));
    uc_assert(uc_mem_read(uc, esp + 12, &buf_size, 4));

    if (handle != 0)
    {
        ret = 0;
        last_error = ERROR_INVALID_HANDLE;
    }
    else
    {
        if (buf_size != 0)
        {
            auto converted = to_utf8string(program_path);
            uint32_t to_copy = converted.size();
            if (to_copy > buf_size)
            {
                last_error = ERROR_INSUFFICIENT_BUFFER;
                to_copy = buf_size;
            }

            uc_assert(uc_mem_write(uc, buf_ptr, converted.data(), to_copy));
            ret = to_copy;
        }
        else
        {
            last_error = ERROR_SUCCESS;
            ret = 0;
        }
    }

    esp += 16;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_kernel32_IsDebuggerPresent(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t ret = 0;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));

    esp += 4;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_kernel32_GetLastError(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t ret = last_error;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));

    esp += 4;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_kernel32_SetLastError(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t new_error;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &new_error, 4));
    last_error = new_error;

    logf("%#010x SetLastError(%#010x)\n", return_addr, new_error);

    esp += 8;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_kernel32_GetEnvironmentStringsW(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t ret = kern32_env_base + offsetof(kernel32_env_t, environment_variables_wide);
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));

    esp += 4;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_kernel32_FreeEnvironmentStringsW(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t ret = 1;

    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    // unused env string ptr

    esp += 8;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_kernel32_GetCommandLineA(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t ret = kern32_env_base + offsetof(kernel32_env_t, cmdline_ascii);
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));

    esp += 4;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_kernel32_GetCommandLineW(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t ret = kern32_env_base + offsetof(kernel32_env_t, cmdline_wide);
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));

    esp += 4;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_kernel32_LCMapStringW(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t codepage;
    uint32_t dw_flags;
    uint32_t src_string_buf; // wchar_t*
    uint32_t src_string_len;
    uint32_t dst_string_buf; // char*
    uint32_t dst_string_len;

    uint32_t target_len = 0;
    uint32_t ret = 0;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &codepage, 4));
    uc_assert(uc_mem_read(uc, esp + 8, &dw_flags, 4));
    uc_assert(uc_mem_read(uc, esp + 12, &src_string_buf, 4));
    uc_assert(uc_mem_read(uc, esp + 16, &src_string_len, 4));
    uc_assert(uc_mem_read(uc, esp + 20, &dst_string_buf, 4));
    uc_assert(uc_mem_read(uc, esp + 24, &dst_string_len, 4));

    if (src_string_buf != 0)
    {
        auto str = read_u16string(uc, src_string_buf);
        if (src_string_len > 0 && str.size() > src_string_len)
            str.resize(src_string_len);

        ret = str.size();

        if ((dw_flags & 0x200) != 0) // LCMAP_UPPERCASE
        {
            for (int i = 0; i < str.size(); i++)
            {
                str[i] = towupper(str[i]);
            }
        }
        else if ((dw_flags & 0x200) != 0) // LCMAP_UPPERCASE
        {
            for (int i = 0; i < str.size(); i++)
            {
                str[i] = towlower(str[i]);
            }
        }
        else
        {
            last_error = ERROR_INVALID_FLAGS;
            ret = 0;
        }

        if (ret != 0 && dst_string_len > 0)
        {
            uint32_t len = ret;
            if (dst_string_len < len)
                len = dst_string_len;

            uc_assert(uc_mem_write(uc, dst_string_buf, str.data(), len * 2));
        }
    }
    else
    {
        last_error = ERROR_INVALID_PARAMETER;
    }

    esp += 28;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_kernel32_GetStringTypeW(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t type;
    uint32_t src_string_buf;
    uint32_t src_string_len;
    uint32_t target_info;
    uint32_t ret = 0;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &type, 4));
    uc_assert(uc_mem_read(uc, esp + 8, &src_string_buf, 4));
    uc_assert(uc_mem_read(uc, esp + 12, &src_string_len, 4));
    uc_assert(uc_mem_read(uc, esp + 16, &target_info, 4));

    if (type < 1 || type > 3 || src_string_buf == 0 || src_string_len == 0 || target_info == 0)
    {
        last_error = ERROR_INVALID_PARAMETER;
    }
    else
    {
        uint16_t *table;
        if (type == 1)
            table = gstw_ct1_table;
        else if (type == 2)
            table = gstw_ct2_table;
        else if (type == 3)
            table = gstw_ct3_table;

        auto str = read_u16string(uc, src_string_buf);
        if (src_string_len > 0 && str.size() > src_string_len)
            str.resize(src_string_len);

        for (int i = 0; i < str.size(); i++)
        {
            uint16_t c = table[str[i]];
            uc_assert(uc_mem_write(uc, target_info + i * 2, &c, 2));
        }
    }

    esp += 20;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_kernel32_MultiByteToWideChar(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t codepage;
    uint32_t dw_flags;
    uint32_t mb_string_buf; // wchar_t*
    uint32_t mb_string_len;
    uint32_t wide_string_buf; // char*
    uint32_t wide_string_len;

    uint32_t target_len = 0;
    uint32_t ret = 0;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &codepage, 4));
    uc_assert(uc_mem_read(uc, esp + 8, &dw_flags, 4));
    uc_assert(uc_mem_read(uc, esp + 12, &mb_string_buf, 4));
    uc_assert(uc_mem_read(uc, esp + 16, &mb_string_len, 4));
    uc_assert(uc_mem_read(uc, esp + 20, &wide_string_buf, 4));
    uc_assert(uc_mem_read(uc, esp + 24, &wide_string_len, 4));

    logf("MultiByteToWideChar(%#010x, %#010x, %#010x, %#010x, %#010x, %#010x)\n", codepage, dw_flags, mb_string_buf, mb_string_len, wide_string_buf, wide_string_len);

    if (mb_string_buf != 0)
    {
        auto mb = read_string(uc, mb_string_buf);
        if (mb_string_len > 0)
        {
            if (mb_string_len < mb.size())
                mb.resize(mb_string_len);
        }

        auto encoded = to_u16string(mb);
        target_len = encoded.size();

        if (wide_string_len != 0)
        {
            if (wide_string_len > target_len)
                target_len = wide_string_len;

            uc_assert(uc_mem_write(uc, wide_string_buf, encoded.data(), target_len));
        }

        ret = target_len;
    }

    logf("-> %d\n", ret);

    esp += 28;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_kernel32_WideCharToMultiByte(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t codepage;
    uint32_t dw_flags;
    uint32_t wide_string_buf; // wchar_t*
    uint32_t wide_string_len;
    uint32_t mb_string_buf; // char*
    uint32_t mb_string_len;
    uint32_t unknown_character_ptr; // const char*
    uint32_t has_used_unk_char_ptr; // uint32_t*

    uint32_t target_len = 0;
    uint32_t ret = 0;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &codepage, 4));
    uc_assert(uc_mem_read(uc, esp + 8, &dw_flags, 4));
    uc_assert(uc_mem_read(uc, esp + 12, &wide_string_buf, 4));
    uc_assert(uc_mem_read(uc, esp + 16, &wide_string_len, 4));
    uc_assert(uc_mem_read(uc, esp + 20, &mb_string_buf, 4));
    uc_assert(uc_mem_read(uc, esp + 24, &mb_string_len, 4));
    uc_assert(uc_mem_read(uc, esp + 28, &unknown_character_ptr, 4));
    uc_assert(uc_mem_read(uc, esp + 32, &has_used_unk_char_ptr, 4));

    logf("WideCharToMultiByte(%#010x, %#010x, %#010x, %#010x, %#010x, %#010x, %#010x, %#010x)\n", codepage, dw_flags, wide_string_buf, wide_string_len, mb_string_buf, mb_string_len, unknown_character_ptr, has_used_unk_char_ptr);

    if (wide_string_buf != 0)
    {
        auto wide = read_u16string(uc, wide_string_buf);
        if (wide_string_len > 0)
        {
            if (wide_string_len < wide.size())
                wide.resize(wide_string_len);
        }

        auto encoded = to_utf8string(wide);
        // logf("encoded = %d // %s)\n", encoded.size(), encoded.c_str());
        target_len = encoded.size();

        if (mb_string_len != 0)
        {
            if (mb_string_len > target_len)
                target_len = mb_string_len;

            uc_assert(uc_mem_write(uc, mb_string_buf, encoded.data(), target_len));
        }

        ret = target_len;
    }

    logf("-> %d\n", ret);

    esp += 36;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_kernel32_GetStdHandle(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t handle_type;
    uint32_t ret = 0;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &handle_type, 4));

    switch (handle_type)
    {
    case STD_INPUT_HANDLE:
        ret = STDIN_HANDLE_VALUE;
        break;
    case STD_OUTPUT_HANDLE:
        ret = STDOUT_HANDLE_VALUE;
        break;
    case STD_ERROR_HANDLE:
        ret = STDERR_HANDLE_VALUE;
        break;
    default:
        break;
    }

    esp += 8;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_kernel32_GetFileType(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t file_handle;
    uint32_t ret = 0;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &file_handle, 4));

    switch (file_handle)
    {
    case STDIN_HANDLE_VALUE:
    case STDOUT_HANDLE_VALUE:
    case STDERR_HANDLE_VALUE:
        ret = 2; // FILE_TYPE_CHAR
        break;
    default:
        // todo interact with real FS
        break;
    }

    esp += 8;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_kernel32_InitializeCriticalSectionAndSpinCount(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t lp_crit_section;
    uint32_t dw_spin_count;
    uint32_t ret = 0;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &lp_crit_section, 4));
    uc_assert(uc_mem_read(uc, esp + 8, &dw_spin_count, 4));

    if (lp_crit_section != 0)
    {
        crit_sections[lp_crit_section] = 0;
        ret = 1;
    }
    logf("%#010x InitializeCriticalSectionAndSpinCount(%#010x, %d) -> %d\n", return_addr, lp_crit_section, dw_spin_count, ret);

    esp += 12;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_kernel32_InitializeCriticalSection(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t lp_crit_section;
    uint32_t ret = 0;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &lp_crit_section, 4));

    if (lp_crit_section != 0)
    {
        crit_sections[lp_crit_section] = 0;
        ret = 1;
    }
    logf("%#010x InitializeCriticalSection(%#010x) -> %d\n", return_addr, lp_crit_section, ret);

    esp += 8;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

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
    logf("%#010x InitializeCriticalSectionEx(%#010x, %d, %#010x) -> %d\n", return_addr, lp_crit_section, dw_spin_count, flags, ret);

    esp += 16;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_kernel32_DeleteCriticalSection(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t lp_crit_section;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &lp_crit_section, 4));

    crit_sections.erase(lp_crit_section);
    logf("%#010x DeleteCriticalSection(%#010x)\n", return_addr, lp_crit_section);

    esp += 8;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_kernel32_EnterCriticalSection(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t lp_crit_section;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &lp_crit_section, 4));

    // no op till we get threading
    logf("%#010x EnterCriticalSection(%#010x)\n", return_addr, lp_crit_section);

    esp += 8;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_kernel32_LeaveCriticalSection(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t lp_crit_section;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &lp_crit_section, 4));

    // no op till we get threading
    logf("%#010x LeaveCriticalSection(%#010x)\n", return_addr, lp_crit_section);

    esp += 8;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_kernel32_TlsAlloc(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t ret = 0xffffffff;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));

    for (uint32_t i = 1; i < 0xffff; i++)
    {
        if (fiber_storage.find(i) == fiber_storage.end())
        {
            ret = i;
            fiber_storage[i] = std::unordered_map<uint32_t, uint32_t>();
            break;
        }
    }
    // todo lasterror

    logf("%#010x TlsAlloc() -> %#010x\n", return_addr, ret);

    esp += 4;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_kernel32_TlsFree(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t index;
    uint32_t ret;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &index, 4));

    ret = fiber_storage.erase(index);

    logf("%#010x TlsFree(%#010x) -> %d\n", return_addr, index, ret);

    esp += 8;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_kernel32_TlsSetValue(uc_engine *uc, uint32_t esp)
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

    logf("%#010x TlsSetValue(%d, %#010x) -> %#010x\n", return_addr, slot, data, ret);
    esp += 12;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_kernel32_TlsGetValue(uc_engine *uc, uint32_t esp)
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

    logf("%#010x TlsGetValue(%d) -> %#010x\n", return_addr, slot, ret);
    esp += 8;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_kernel32_FlsAlloc(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t callback;
    uint32_t ret = 0xffffffff;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &callback, 4));

    for (uint32_t i = 1; i < 0xffff; i++)
    {
        if (fiber_storage.find(i) == fiber_storage.end())
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

    logf("%#010x FlsAlloc(%#010x) -> %#010x\n", return_addr, callback, ret);

    esp += 8;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_kernel32_FlsFree(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t index;
    uint32_t ret;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &index, 4));

    ret = fiber_storage.erase(index);
    fiber_callbacks.erase(index); // no stuff we run uses fibers so we will ignore the callback for now.

    logf("%#010x FlsFree(%#010x) -> %#010x\n", return_addr, index, ret);

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

    logf("%#010x FlsSetValue(%d, %#010x) -> %#010x\n", return_addr, slot, data, ret);
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

    logf("%#010x FlsGetValue(%d) -> %#010x\n", return_addr, slot, ret);
    esp += 8;
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
    logf("%#010x HeapCreate(%#010x, %d, %d) -> %#010x\n", return_addr, fl_options, initial_size, max_size, ret);

    esp += 16;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_kernel32_HeapDestroy(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t heap_handle;
    uint32_t ret = 1;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &heap_handle, 4));

    logf("%#010x HeapDestroy(%#010x) -> %d\n", return_addr, heap_handle, ret);

    esp += 8;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_kernel32_HeapAlloc(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t heap_handle;
    uint32_t flags;
    uint32_t size;
    uint32_t ret = 0;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &heap_handle, 4));
    uc_assert(uc_mem_read(uc, esp + 8, &flags, 4));
    uc_assert(uc_mem_read(uc, esp + 12, &size, 4));

    void *host_ptr = tinyalloc::ta_alloc(&allocator, size);
    if (host_ptr != nullptr)
    {
        if (flags & 0x08)
        { // HEAP_ZERO_MEMORY
            memset(host_ptr, 0, size);
        }

        uintptr_t ptr = uintptr_t(host_ptr) - uintptr_t(heap) + heap_base;
        ret = ptr;
    }

    logf("%#010x HeapAlloc(%#010x, %#010x, %d) -> %#010x\n", return_addr, heap_handle, flags, size, ret);

    esp += 16;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_kernel32_HeapFree(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t heap_handle;
    uint32_t flags;
    uint32_t ptr;
    uint32_t ret = 0;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &heap_handle, 4));
    uc_assert(uc_mem_read(uc, esp + 8, &flags, 4));
    uc_assert(uc_mem_read(uc, esp + 12, &ptr, 4));

    if (ptr != 0)
    {
        void *host_ptr = (void *)(uintptr_t(ptr) + uintptr_t(heap) - heap_base);
        ret = 1;

        tinyalloc::ta_free(&allocator, (void *)host_ptr);
    }

    logf("%#010x HeapFree(%#010x, %#010x, %#010x) -> %#010x\n", return_addr, heap_handle, flags, ptr, ret);

    esp += 16;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
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

static void cb_kernel32_HeapSize(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t heap_handle;
    uint32_t flags;
    uint32_t ptr;
    int32_t ret = 0;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &heap_handle, 4));
    uc_assert(uc_mem_read(uc, esp + 8, &flags, 4));
    uc_assert(uc_mem_read(uc, esp + 12, &ptr, 4));

    if (ptr != 0)
    {
        void *host_ptr = (void *)(uintptr_t(ptr) + uintptr_t(heap) - heap_base);
        ret = tinyalloc::ta_blocksize(&allocator, (void *)host_ptr);
    }

    if (ret == 0)
        ret = -1;

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

static uint32_t handle_from(std::u16string const &name)
{
    auto lname = to_lower(name);
    if (lname == u"user32.dll")
    {
        return user32_handle;
    }
    else if (lname == u"kernel32.dll")
    {
        return kernel32_handle;
    }
    else if (lname == u"gdi32.dll")
    {
        return gdi32_handle;
    }
    else if (lname == u"winmm.dll")
    {
        return winmm_handle;
    }
    else if (lname == u"msvcrt.dll")
    {
        return msvcrt_handle;
    }
    else if (lname == u"msvcr100.dll")
    {
        return msvcr100_handle;
    }
    else
    {
        return 0;
    }
}

static void cb_kernel32_LoadLibraryExW(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t lib_name;
    uint32_t ignored;
    uint32_t flags;
    uint32_t ret = 0;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &lib_name, 4));
    uc_assert(uc_mem_read(uc, esp + 8, &ignored, 4));
    uc_assert(uc_mem_read(uc, esp + 12, &flags, 4));

    if (lib_name != 0)
    {
        auto file = read_u16string(uc, lib_name);
        ret = handle_from(file);

        printf("LoadLibraryExW(\"%s\", %#010x, %#010x) -> %#06x\n", to_utf8string(file).c_str(), ignored, flags, ret);
    }

    esp += 16;

    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_kernel32_GetModuleHandleExW(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t name_addr;
    uint32_t flags;
    uint32_t handle_addr;
    uint32_t ret = 0;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &name_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 8, &flags, 4));
    uc_assert(uc_mem_read(uc, esp + 12, &handle_addr, 4));
    esp += 16;

    if (name_addr == 0)
    {
        uc_assert(uc_mem_write(uc, handle_addr, &curr_module_handle, 4));
        ret = 1;
    }
    else
    {
        auto mod_name = read_u16string(uc, name_addr);
        auto handle = handle_from(mod_name);
        if (handle != 0)
        {
            ret = 1;
            uc_assert(uc_mem_write(uc, handle_addr, &handle, 4));
        }

        //logf("GetModuleHandle(%s) called\n", mod_name.c_str());
    }

    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
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
    }
    else
    {
        auto mod_name = read_u16string(uc, name_addr);
        ret = handle_from(mod_name);

        //logf("GetModuleHandle(%s) called\n", mod_name.c_str());
    }

    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_kernel32_GetProcAddress(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t mod_handle;
    uint32_t name_addr;
    uint32_t ret = 0;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &mod_handle, 4));
    uc_assert(uc_mem_read(uc, esp + 8, &name_addr, 4));
    esp += 12;

    auto sym_name = read_string(uc, name_addr);
    auto cache_entry = import_cache.find(sym_name);
    if (cache_entry != import_cache.end())
    {
        ret = cache_entry->second;
    }
    else
    {
        auto ex = exports.find(sym_name);
        if (ex != exports.end())
        {
            uint32_t addr = 0;
            auto cached = import_cache.find(sym_name);
            if (cached != import_cache.end())
            {
                addr = cached->second;
            }
            else if (ex->second.raw_address != 0)
            {
                addr = ex->second.raw_address;
                import_cache[sym_name] = addr;
            }
            else if (ex->second.raw_code != nullptr)
            {
                addr = push_jitregion(uc, ex->second.raw_code, ex->second.raw_code_size);
                import_cache[sym_name] = addr;
            }
            else if (ex->second.cb != nullptr)
            {
                addr = add_syscall(uc, thunk_cbs.size(), ex->second.cb);
                import_cache[sym_name] = addr;
            }

            ret = addr;
        }
    }

    logf("%#010x GetProcAddress(%#010x, %s) -> %#010x\n", return_addr, mod_handle, sym_name.c_str(), ret);

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

    printf("%#010x InterlockedCompareExchange(%#010x, %#010x, %#010x) %#010x\n", return_addr, dest_addr, exchange, comperand, og_value);

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

static void cb_kernel32_InterlockedIncrement(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t dest_addr;
    uint32_t og_value;

    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &dest_addr, 4));
    esp += 8;

    uc_assert(uc_mem_read(uc, dest_addr, &og_value, 4));
    og_value += 1;
    uc_assert(uc_mem_write(uc, dest_addr, &og_value, 4));

    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &og_value));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_kernel32_InterlockedDecrement(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t dest_addr;
    uint32_t og_value;

    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &dest_addr, 4));
    esp += 8;

    uc_assert(uc_mem_read(uc, dest_addr, &og_value, 4));
    og_value -= 1;
    uc_assert(uc_mem_write(uc, dest_addr, &og_value, 4));

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

    if (ptr_in != 0)
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

    if (ptr_in != 0)
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

    logf("%#010x Sleep(%d)\n", return_addr, time);

    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
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

static void cb_kernel32_UnhandledExceptionFilter(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t addr = 0;
    uint32_t ret = 1;

    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &addr, 4));

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

static void cb_kernel32_GetACP(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t ret = 65001; // UTF-8
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));

    esp += 4;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_kernel32_IsValidCodePage(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t code_page;
    uint32_t ret = 0;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &code_page, 4));

    if (code_page == 65001)
    {
        ret = 1;
    }

    esp += 8;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_kernel32_SetHandleCount(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t ret;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &ret, 4));

    esp += 8;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_kernel32_GetCPInfo(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t code_page;
    uint32_t cpinfo_ptr;
    uint32_t ret = 0;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &code_page, 4));
    uc_assert(uc_mem_read(uc, esp + 8, &cpinfo_ptr, 4));

    if (code_page == 65001)
    {
        uint32_t max_char_size = 4;
        char def_char[2] = "?";
        uint8_t lead_bytes[12] = {0x00, 0x00, 0x2e, 0x00, 0x00, 0x00, 0x94, 0x1c, 0x12, 0x00, 0x28, 0xff};

        uc_assert(uc_mem_write(uc, cpinfo_ptr, &max_char_size, 4));
        uc_assert(uc_mem_write(uc, cpinfo_ptr + 4, &def_char, sizeof(def_char)));
        uc_assert(uc_mem_write(uc, cpinfo_ptr + 6, &lead_bytes, sizeof(lead_bytes)));
        ret = 1;
    }
    else
    {
        last_error = ERROR_INVALID_PARAMETER;
    }

    esp += 12;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

void install_kernel32_exports(uc_engine *uc)
{
    {
        kernel32_env_t *env = new kernel32_env_t();
        kern32_env_size = align_address(sizeof(kernel32_env_t));
        uc_assert(uc_mem_map(uc, kern32_env_base, kern32_env_size, UC_PROT_READ | UC_PROT_WRITE));
        uc_assert(uc_mem_write(uc, kern32_env_base, env, sizeof(kernel32_env_t)));

        auto heap_end = (void *)((char *)heap + heap_size);
        tinyalloc::ta_init(&allocator, heap, heap_end, 1024 * 32, 16, 4);

        delete env;
    }

    ptr_secret = random() ^ random() ^ random() - 0xf35d7c1a;

    Export FindFirstFileW_ex = {"FindFirstFileW", cb_kernel32_FindFirstFileW};
    exports["FindFirstFileW"] = FindFirstFileW_ex;

    Export CreateDirectoryW_ex = {"CreateDirectoryW", cb_kernel32_CreateDirectoryW};
    exports["CreateDirectoryW"] = CreateDirectoryW_ex;

    Export GetModuleFileNameW_ex = {"GetModuleFileNameW", cb_kernel32_GetModuleFileNameW};
    exports["GetModuleFileNameW"] = GetModuleFileNameW_ex;

    Export GetModuleFileNameA_ex = {"GetModuleFileNameA", cb_kernel32_GetModuleFileNameA};
    exports["GetModuleFileNameA"] = GetModuleFileNameA_ex;

    Export IsDebuggerPresent_ex = {"IsDebuggerPresent", cb_kernel32_IsDebuggerPresent};
    exports["IsDebuggerPresent"] = IsDebuggerPresent_ex;

    Export GetLastError_ex = {"GetLastError", cb_kernel32_GetLastError};
    exports["GetLastError"] = GetLastError_ex;

    Export SetLastError_ex = {"SetLastError", cb_kernel32_SetLastError};
    exports["SetLastError"] = SetLastError_ex;

    Export LCMapStringW_ex = {"LCMapStringW", cb_kernel32_LCMapStringW};
    exports["LCMapStringW"] = LCMapStringW_ex;

    Export GetStringTypeW_ex = {"GetStringTypeW", cb_kernel32_GetStringTypeW};
    exports["GetStringTypeW"] = GetStringTypeW_ex;

    Export MultiByteToWideChar_ex = {"MultiByteToWideChar", cb_kernel32_MultiByteToWideChar};
    exports["MultiByteToWideChar"] = MultiByteToWideChar_ex;

    Export WideCharToMultiByte_ex = {"WideCharToMultiByte", cb_kernel32_WideCharToMultiByte};
    exports["WideCharToMultiByte"] = WideCharToMultiByte_ex;

    Export GetEnvironmentStringsW_ex = {"GetEnvironmentStringsW", cb_kernel32_GetEnvironmentStringsW};
    exports["GetEnvironmentStringsW"] = GetEnvironmentStringsW_ex;

    Export FreeEnvironmentStringsW_ex = {"FreeEnvironmentStringsW", cb_kernel32_FreeEnvironmentStringsW};
    exports["FreeEnvironmentStringsW"] = FreeEnvironmentStringsW_ex;

    Export GetCommandLineA_ex = {"GetCommandLineA", cb_kernel32_GetCommandLineA};
    exports["GetCommandLineA"] = GetCommandLineA_ex;

    Export GetCommandLineW_ex = {"GetCommandLineW", cb_kernel32_GetCommandLineW};
    exports["GetCommandLineW"] = GetCommandLineW_ex;

    Export GetStdHandle_ex = {"GetStdHandle", cb_kernel32_GetStdHandle};
    exports["GetStdHandle"] = GetStdHandle_ex;

    Export GetFileType_ex = {"GetFileType", cb_kernel32_GetFileType};
    exports["GetFileType"] = GetFileType_ex;

    Export InitializeCriticalSectionAndSpinCount_ex = {"InitializeCriticalSectionAndSpinCount", cb_kernel32_InitializeCriticalSectionAndSpinCount};
    exports["InitializeCriticalSectionAndSpinCount"] = InitializeCriticalSectionAndSpinCount_ex;

    Export InitializeCriticalSection_ex = {"InitializeCriticalSection", cb_kernel32_InitializeCriticalSection};
    exports["InitializeCriticalSection"] = InitializeCriticalSection_ex;

    Export InitializeCriticalSectionEx_ex = {"InitializeCriticalSectionEx", cb_kernel32_InitializeCriticalSectionEx};
    exports["InitializeCriticalSectionEx"] = InitializeCriticalSectionEx_ex;

    Export DeleteCriticalSection_ex = {"DeleteCriticalSection", cb_kernel32_DeleteCriticalSection};
    exports["DeleteCriticalSection"] = DeleteCriticalSection_ex;

    Export EnterCriticalSection_ex = {"EnterCriticalSection", cb_kernel32_EnterCriticalSection};
    exports["EnterCriticalSection"] = EnterCriticalSection_ex;

    Export LeaveCriticalSection_ex = {"LeaveCriticalSection", cb_kernel32_LeaveCriticalSection};
    exports["LeaveCriticalSection"] = LeaveCriticalSection_ex;

    Export TlsAlloc_ex = {"TlsAlloc", cb_kernel32_TlsAlloc};
    exports["TlsAlloc"] = TlsAlloc_ex;

    Export TlsFree_ex = {"TlsFree", cb_kernel32_TlsFree};
    exports["TlsFree"] = TlsFree_ex;

    Export TlsSetValue_ex = {"TlsSetValue", cb_kernel32_TlsSetValue};
    exports["TlsSetValue"] = TlsSetValue_ex;

    Export TlsGetValue_ex = {"TlsGetValue", cb_kernel32_TlsGetValue};
    exports["TlsGetValue"] = TlsGetValue_ex;

    Export FlsAlloc_ex = {"FlsAlloc", cb_kernel32_FlsAlloc};
    exports["FlsAlloc"] = FlsAlloc_ex;

    Export FlsFree_ex = {"FlsFree", cb_kernel32_FlsFree};
    exports["FlsFree"] = FlsFree_ex;

    Export FlsSetValue_ex = {"FlsSetValue", cb_kernel32_FlsSetValue};
    exports["FlsSetValue"] = FlsSetValue_ex;

    Export FlsGetValue_ex = {"FlsGetValue", cb_kernel32_FlsGetValue};
    exports["FlsGetValue"] = FlsGetValue_ex;

    Export HeapCreate_ex = {"HeapCreate", cb_kernel32_HeapCreate};
    exports["HeapCreate"] = HeapCreate_ex;

    Export HeapDestroy_ex = {"HeapDestroy", cb_kernel32_HeapDestroy};
    exports["HeapDestroy"] = HeapDestroy_ex;

    Export HeapAlloc_ex = {"HeapAlloc", cb_kernel32_HeapAlloc};
    exports["HeapAlloc"] = HeapAlloc_ex;

    Export HeapFree_ex = {"HeapFree", cb_kernel32_HeapFree};
    exports["HeapFree"] = HeapFree_ex;

    Export HeapSetInformation_ex = {"HeapSetInformation", cb_kernel32_HeapSetInformation};
    exports["HeapSetInformation"] = HeapSetInformation_ex;

    Export HeapSize_ex = {"HeapSize", cb_kernel32_HeapSize};
    exports["HeapSize"] = HeapSize_ex;

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

    Export LoadLibraryExW_ex = {"LoadLibraryExW", cb_kernel32_LoadLibraryExW};
    exports["LoadLibraryExW"] = LoadLibraryExW_ex;

    Export GetModuleHandleW_ex = {"GetModuleHandleW", cb_kernel32_GetModuleHandleW};
    exports["GetModuleHandleW"] = GetModuleHandleW_ex;

    Export GetModuleHandleExW_ex = {"GetModuleHandleExW", cb_kernel32_GetModuleHandleExW};
    exports["GetModuleHandleExW"] = GetModuleHandleExW_ex;

    Export GetProcAddress_ex = {"GetProcAddress", cb_kernel32_GetProcAddress};
    exports["GetProcAddress"] = GetProcAddress_ex;

    Export GetCurrentThreadId_ex = {"GetCurrentThreadId", cb_kernel32_GetCurrentThreadId};
    exports["GetCurrentThreadId"] = GetCurrentThreadId_ex;

    Export QueryPerformanceCounter_ex = {"QueryPerformanceCounter", cb_kernel32_QueryPerformanceCounter};
    exports["QueryPerformanceCounter"] = QueryPerformanceCounter_ex;

    Export GetTickCount_ex = {"GetTickCount", cb_kernel32_GetTickCount};
    exports["GetTickCount"] = GetTickCount_ex;

    Export GetStartupInfoW_ex = {"GetStartupInfoW", cb_kernel32_GetStartupInfoW};
    exports["GetStartupInfoW"] = GetStartupInfoW_ex;

    Export InterlockedCompareExchange_ex = {"InterlockedCompareExchange", cb_kernel32_InterlockedCompareExchange};
    exports["InterlockedCompareExchange"] = InterlockedCompareExchange_ex;

    Export InterlockedExchange_ex = {"InterlockedExchange", cb_kernel32_InterlockedExchange};
    exports["InterlockedExchange"] = InterlockedExchange_ex;

    Export InterlockedIncrement_ex = {"InterlockedIncrement", cb_kernel32_InterlockedIncrement};
    exports["InterlockedIncrement"] = InterlockedIncrement_ex;

    Export InterlockedDecrement_ex = {"InterlockedDecrement", cb_kernel32_InterlockedDecrement};
    exports["InterlockedDecrement"] = InterlockedDecrement_ex;

    Export EncodePointer_ex = {"EncodePointer", cb_kernel32_EncodePointer};
    exports["EncodePointer"] = EncodePointer_ex;

    Export DecodePointer_ex = {"DecodePointer", cb_kernel32_DecodePointer};
    exports["DecodePointer"] = DecodePointer_ex;

    Export IsProcessorFeaturePresent_ex = {"IsProcessorFeaturePresent", cb_kernel32_IsProcessorFeaturePresent};
    exports["IsProcessorFeaturePresent"] = IsProcessorFeaturePresent_ex;

    Export UnhandledExceptionFilter_ex = {"UnhandledExceptionFilter", cb_kernel32_UnhandledExceptionFilter};
    exports["UnhandledExceptionFilter"] = UnhandledExceptionFilter_ex;

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

    Export GetACP_ex = {"GetACP", cb_kernel32_GetACP};
    exports["GetACP"] = GetACP_ex;

    Export IsValidCodePage_ex = {"IsValidCodePage", cb_kernel32_IsValidCodePage};
    exports["IsValidCodePage"] = IsValidCodePage_ex;

    Export SetHandleCount_ex = {"SetHandleCount", cb_kernel32_SetHandleCount};
    exports["SetHandleCount"] = SetHandleCount_ex;

    Export GetCPInfo_ex = {"GetCPInfo", cb_kernel32_GetCPInfo};
    exports["GetCPInfo"] = GetCPInfo_ex;
}