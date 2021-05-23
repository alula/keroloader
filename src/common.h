#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>
#include <unicorn/unicorn.h>

#define __MSABI_LONG(x) ((uint32_t)x)

typedef uint32_t DWORD;
typedef uint16_t WORD;
typedef uint8_t BYTE;
typedef char16_t WCHAR;
typedef uint32_t HANDLE;
typedef uint32_t LPWSTR;
typedef uint32_t LPBYTE;

static constexpr uint32_t INVALID_HANDLE_VALUE = 0xffffffff;
static constexpr uint32_t STDIN_HANDLE_VALUE = 0x800;
static constexpr uint32_t STDOUT_HANDLE_VALUE = 0x801;
static constexpr uint32_t STDERR_HANDLE_VALUE = 0x802;
static constexpr uint32_t FILE_HANDLE_VALUE_OFFSET = 0x1000;

enum STDIO_HANDLE
{
    STD_INPUT_HANDLE = 10,
    STD_OUTPUT_HANDLE = 11,
    STD_ERROR_HANDLE = 12,
};

class ThreadCtx
{
public:
    uint32_t thread_id = 0;
    uint32_t eax = 0;
    uint32_t ebx = 0;
    uint32_t ecx = 0;
    uint32_t edx = 0;
    uint32_t esi = 0;
    uint32_t edi = 0;
    uint32_t eip = 0;
    uint32_t esp = 0;
    uint32_t ebp = 0;
    uint32_t eflags = 0;
    void *stack = nullptr;
    void *stack_end = nullptr;
    void *teb = nullptr;

    ThreadCtx();
    ~ThreadCtx();

    void save_regs(uc_engine *uc);
    void restore_regs(uc_engine *uc);
    void print_stack(uc_engine *uc);
    void print_regs();
};

extern int window_width;
extern int window_height;

extern uint32_t curr_thread;
extern ThreadCtx *curr_thread_ref;
extern uint32_t curr_module_handle;

extern void *heap;
extern uint32_t heap_size;
extern uint32_t heap_base;
extern uint32_t stack_base;
extern uint32_t stack_size;
extern uint32_t emu_spinlock_thunk;
extern uint32_t emu_spinlock_lock;
extern bool emu_failed;
extern bool emu_nointerrupt;

extern uint32_t last_error;
extern char msgbox_title_txt[2048];
extern char msgbox_message_txt[4096];

extern std::unordered_map<std::string, uint32_t> import_cache;
extern std::vector<void (*)(uc_engine *uc, uint32_t esp)> thunk_cbs;

extern uint32_t add_syscall(uc_engine *uc, uint32_t id, void (*cb)(uc_engine *, uint32_t));
extern void logf(const char *fmt, ...);
extern void uc_assert(uc_err err, const std::string &msg = "Assertion failed");
extern uint32_t push_jitregion(uc_engine *uc, const uint8_t *code, size_t code_size);

template <typename T>
extern std::string int_to_hex(T i);
extern std::pair<std::string, std::string> split_unix_path(std::string const &u);
extern std::string to_unix_path(std::u16string const &u);
extern std::u16string to_upper(std::u16string const &u);
extern std::u16string to_lower(std::u16string const &u);
extern std::string to_utf8string(std::u16string const &u);
extern std::u16string to_u16string(std::string const &u);
extern std::u16string read_u16string(uc_engine *uc, uint32_t address);
extern std::string read_string(uc_engine *uc, uint32_t address);

extern void *kernel32_host_malloc(uintptr_t *emu_addr, size_t size);
extern void kernel32_host_free(void *mem);

static inline constexpr uint32_t align_address(uint32_t addr, uint32_t alignment = 0x1000)
{
    return (addr + alignment - 1) & ~(alignment - 1);
}