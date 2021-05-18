#pragma once

#include <cstdint>
#include <string>
#include <unicorn/unicorn.h>

typedef uint32_t DWORD;
typedef uint16_t WORD;
typedef uint8_t BYTE;
typedef char16_t WCHAR;
typedef uint32_t HANDLE;
typedef uint32_t LPWSTR;
typedef uint32_t LPBYTE;

extern uint32_t curr_thread;
extern uint32_t curr_module_handle;

extern void *heap;
extern uint32_t heap_size;
extern uint32_t heap_base;
extern uint32_t emu_spinlock_thunk;
extern uint32_t emu_spinlock_lock;
extern bool emu_failed;

extern char msgbox_title_txt[2048];
extern char msgbox_message_txt[4096];

extern void add_syscall(uint32_t id, void (*cb)(uc_engine* uc, uint32_t esp));
extern void logf(const char *fmt, ...);
extern void uc_assert(uc_err err, const std::string &msg = "Assertion failed");
extern uint32_t push_jitregion(uc_engine* uc, const uint8_t* code, size_t code_size);

extern std::u16string read_u16string(uc_engine* uc, uint32_t address);

static inline constexpr uint32_t align_address(uint32_t addr, uint32_t alignment = 0x1000)
{
    return (addr + alignment - 1) & ~(alignment - 1);
}