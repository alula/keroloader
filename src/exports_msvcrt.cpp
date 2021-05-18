#include <cstdint>
#include <cstring>
#include "common.h"
#include "exports.h"
#include "tinyalloc/tinyalloc.h"

/*
__getmainargs:
    mov    edx, DWORD PTR ds:0xf000200c
    mov    eax, DWORD PTR [esp+0x4]
    mov    DWORD PTR [eax],edx
    mov    eax, DWORD PTR [esp+0x8]
    mov    DWORD PTR [eax],0xf0002010
    mov    eax, DWORD PTR [esp+0xc]
    mov    DWORD PTR [eax],0xf0002010
    mov    eax, 0x0
    ret 
*/
static uint8_t code_msvcrt_getmainargs[] = {0x8B, 0x15, 0x0C, 0x20, 0x00, 0xF0, 0x8B, 0x44, 0x24, 0x04, 0x89,
                                            0x10, 0x8B, 0x44, 0x24, 0x08, 0xC7, 0x00, 0x10, 0x20, 0x00, 0xF0,
                                            0x8B, 0x44, 0x24, 0x0C, 0xC7, 0x00, 0x10, 0x20, 0x00, 0xF0, 0xB8,
                                            0x00, 0x00, 0x00, 0x00, 0xC3};

/*
_initterm:
    push    esi
    push    ebx
    sub     esp, 4
    mov     ebx, DWORD PTR [esp+16]
    mov     esi, DWORD PTR [esp+20]
L1:
    mov     eax, DWORD PTR [ebx]
    add     ebx, 4
    test    eax, eax
    je      L2
    call    eax
L2:
    cmp     ebx, esi
    jb      L1
    add     esp, 4
    pop     ebx
    pop     esi
    ret
 */
static uint8_t code_msvcrt_initterm[] = {0x56, 0x53, 0x83, 0xEC, 0x04, 0x8B, 0x5C, 0x24, 0x10, 0x8B,
                                         0x74, 0x24, 0x14, 0x8B, 0x03, 0x83, 0xC3, 0x04, 0x85, 0xC0,
                                         0x74, 0x02, 0xFF, 0xD0, 0x39, 0xF3, 0x72, 0xF1, 0x83, 0xC4,
                                         0x04, 0x5B, 0x5E, 0xC3};

/*
_ret:
    ret 
 */
static uint8_t code_ret[] = {0xc3};

static uint8_t code_ret_clean4[] = {0xc2, 0x04, 0x00}; // ret 4
static uint8_t code_ret_clean8[] = {0xc2, 0x08, 0x00}; // ret 8
static uint8_t code_ret_clean12[] = {0xc2, 0x0c, 0x00}; // ret 12
static uint8_t code_ret_clean16[] = {0xc2, 0x10, 0x00}; // ret 16

// 0xf0002000: uint32_t fmode
// 0xf0002004: uint32_t conmode
// 0xf000200c: int fake_argc = 1
// 0xf0002010: char* fake_argv[0] = {0xf0002010}
// 0xf0002050: char* fake_envp[2] = {0xf0002100, 0}
// 0xf0002100: char fake_arg0[]
// 0xf0002200: char fake_env[]

/*
_p_fmode:
    mov eax, fmode
    ret
 */
static uint8_t code_p_fmode[] = {0xB8, 0x00, 0x20, 0x00, 0xF0, 0xC3};
static uint8_t code_p_commode[] = {0xB8, 0x04, 0x20, 0x00, 0xF0, 0xC3};

/*
; ported from https://github.com/bitwiseworks/libc/blob/master/testcase/floatingpoint/control87-linux.s
_control87:
    push   ecx
    fstcw  WORD PTR [esp]
    mov    ecx, DWORD PTR [esp+0xc]
    jecxz  lbl
    mov    edx, DWORD PTR [esp+0x8]
    and    edx, ecx
    not    ecx
    mov    eax, DWORD PTR [esp]
    and    eax, ecx
    or     eax, edx
    mov    WORD PTR [esp+0x2], ax
    fldcw  WORD PTR [esp+0x2]
lbl:
    pop    eax
    movzx  eax, ax
    ret 
 */
static uint8_t code_control87[] = {0x51, 0x9B, 0xD9, 0x3C, 0x24, 0x8B, 0x4C, 0x24, 0x0C, 0xE3, 0x18,
                                   0x8B, 0x54, 0x24, 0x08, 0x21, 0xCA, 0xF7, 0xD1, 0x8B, 0x04, 0x24,
                                   0x21, 0xC8, 0x09, 0xD0, 0x66, 0x89, 0x44, 0x24, 0x02, 0xD9, 0x6C,
                                   0x24, 0x02, 0x58, 0x0F, 0xB7, 0xC0, 0xC3};

uint32_t onexit_handler = 0;

static void cb_msvcrt_onexit(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t onexit_new_handler = 0;

    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &onexit_new_handler, 4));

    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &onexit_new_handler));
    onexit_handler = onexit_new_handler;

    esp += 4;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_msvcrt_malloc(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t size = 0;
    uint32_t real_addr = 0;

    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &size, 4));
    esp += 4;

    void *mem = ta_alloc(size);
    if (mem != nullptr)
    {
        uintptr_t offset = (uintptr_t)mem - (uintptr_t)heap + heap_base;
        real_addr = offset;

        logf("memory alloc: %#010x, size = %d\n", real_addr, size);
    }

    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &real_addr));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_msvcrt_free(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t addr = 0;
    uint32_t ret = 0;

    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &addr, 4));
    esp += 4;

    if (addr >= heap_base && addr <= (heap_base + heap_size))
    {
        logf("memory free: %#010x\n", addr);

        auto offset = (void *)((uintptr_t)addr + (uintptr_t)heap - heap_base);
        ta_free(offset);
    }

    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static uint8_t code_memset[] = {0x56, 0x53, 0x8B, 0x5C, 0x24, 0x0C, 0x8B, 0x74, 0x24, 0x14, 0x0F,
                                0xB6, 0x4C, 0x24, 0x10, 0x8D, 0x14, 0x33, 0x85, 0xF6, 0x74, 0x0B,
                                0x89, 0xD8, 0x88, 0x08, 0x83, 0xC0, 0x01, 0x39, 0xD0, 0x75, 0xF7,
                                0x89, 0xD8, 0x5B, 0x5E, 0xC3};

static uint8_t code_memcpy[] = {0x56, 0x53, 0x8B, 0x5C, 0x24, 0x14, 0x8B, 0x74, 0x24, 0x0C, 0x85,
                                0xDB, 0x74, 0x18, 0x8B, 0x44, 0x24, 0x10, 0x89, 0xF2, 0x01, 0xC3,
                                0x0F, 0xB6, 0x08, 0x83, 0xC0, 0x01, 0x83, 0xC2, 0x01, 0x88, 0x4A,
                                0xFF, 0x39, 0xD8, 0x75, 0xF0, 0x89, 0xF0, 0x5B, 0x5E, 0xC3};


static void cb_msvcrt_amsg_exit(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr = 0xdeadbeef;
    uint32_t code = 0;
    uint32_t ret = 0;

    //uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &code, 4));
    esp += 4;

    strcpy(msgbox_title_txt, "MSVCRT error");
    switch (code) {
    case 0:
        strcpy(msgbox_message_txt, "Stack overflow.");
        break;
    case 2:
        strcpy(msgbox_message_txt, "Floating point exception.");
        break;
    case 3:
        strcpy(msgbox_message_txt, "Integer division by zero.");
        break;
    case 8:
        strcpy(msgbox_message_txt, "No space for arguments.");
        break;
    case 9:
        strcpy(msgbox_message_txt, "No space for environment.");
        break;
    case 10:
        strcpy(msgbox_message_txt, "Program aborted.");
        break;
    case 16:
        strcpy(msgbox_message_txt, "No space for thread data.");
        break;
    case 17:
        strcpy(msgbox_message_txt, "Lock error.");
        break;
    case 18:
        strcpy(msgbox_message_txt, "Heap error.");
        break;
    case 19:
        strcpy(msgbox_message_txt, "Cannot open console device.");
        break;
    case 22:
        strcpy(msgbox_message_txt, "Non-continuable exception.");
        break;
    case 23:
        strcpy(msgbox_message_txt, "Invalid exception disposition.");
        break;
    case 24:
        strcpy(msgbox_message_txt, "No space for _onexit table.");
        break;
    case 25:
        strcpy(msgbox_message_txt, "Pure virtual function call.");
        break;
    case 26:
        strcpy(msgbox_message_txt, "No space for stdio initialization.");
        break;
    case 27:
        strcpy(msgbox_message_txt, "No space for lowio initialization.");
        break;
    case 28:
        strcpy(msgbox_message_txt, "Cannot initalize heap.");
        break;
    case 30:
        strcpy(msgbox_message_txt, "CRT has not been initialized.");
        break;
    case 31:
        strcpy(msgbox_message_txt, "Attempted to initialize CRT twice.");
        break;
    default:
        sprintf(msgbox_message_txt, "Unknown error code: %d.", code);
        break;
    }

    emu_failed = true;
    uc_assert(uc_emu_stop(uc));
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

void install_msvcrt_exports(uc_engine *uc)
{
    uint32_t msvcrt_env = 0xf0002000;
    uint32_t fake_argc = 1;
    uint32_t fake_argv[2] = {0xf0002100};
    uint32_t fake_envp[2] = {0xf0002200, 0};

    logf("Initializing vcrt structure stubs...\n");
    uc_assert(uc_mem_map(uc, msvcrt_env, 0x2000, UC_PROT_READ | UC_PROT_WRITE));
    uc_assert(uc_mem_write(uc, msvcrt_env + 0x0c, &fake_argc, sizeof(fake_argc)));
    uc_assert(uc_mem_write(uc, msvcrt_env + 0x10, &fake_argv, sizeof(fake_argv)));
    uc_assert(uc_mem_write(uc, msvcrt_env + 0x50, &fake_envp, sizeof(fake_envp)));

    logf("Initializing memory allocator...\n");
    auto heap_end = (void *)((char *)heap + heap_size);
    ta_init(heap, heap_end, 1024 * 32, 16, 4);

    Export __getmainargs_ex = {"__getmainargs", nullptr, code_msvcrt_getmainargs, sizeof(code_msvcrt_getmainargs)};
    exports["__getmainargs"] = __getmainargs_ex;

    Export __wgetmainargs_ex = {"__wgetmainargs", nullptr, code_msvcrt_getmainargs, sizeof(code_msvcrt_getmainargs)};
    exports["__wgetmainargs"] = __wgetmainargs_ex;

    Export _initterm_ex = {"_initterm", nullptr, code_msvcrt_initterm, sizeof(code_msvcrt_initterm)};
    exports["_initterm"] = _initterm_ex;

    Export _initterm_e_ex = {"_initterm_e", nullptr, code_msvcrt_initterm, sizeof(code_msvcrt_initterm)};
    exports["_initterm_e"] = _initterm_e_ex;

    Export __set_app_type_ex = {"__set_app_type", nullptr, code_ret, sizeof(code_ret)};
    exports["__set_app_type"] = __set_app_type_ex;

    Export __lconv_init_ex = {"__lconv_init", nullptr, code_ret, sizeof(code_ret)};
    exports["__lconv_init"] = __lconv_init_ex;

    Export __setusermatherr_ex = {"__setusermatherr", nullptr, code_ret, sizeof(code_ret)};
    exports["__setusermatherr"] = __setusermatherr_ex;

    Export _configthreadlocale_ex = {"_configthreadlocale", nullptr, code_ret, sizeof(code_ret)};
    exports["_configthreadlocale"] = _configthreadlocale_ex;

    Export __p__fmode_ex = {"__p__fmode", nullptr, code_p_fmode, sizeof(code_p_fmode)};
    exports["__p__fmode"] = __p__fmode_ex;

    Export __p__commode_ex = {"__p__commode", nullptr, code_p_commode, sizeof(code_p_commode)};
    exports["__p__commode"] = __p__commode_ex;

    Export _control87_ex = {"_control87", nullptr, code_control87, sizeof(code_control87)};
    exports["_control87"] = _control87_ex;

    Export _controlfp_s_ex = {"_controlfp_s", nullptr, code_control87, sizeof(code_control87)};
    exports["_controlfp_s"] = _controlfp_s_ex;

    Export memset_ex = {"memset", nullptr, code_memset, sizeof(code_memset)};
    exports["memset"] = memset_ex;

    Export memcpy_ex = {"memcpy", nullptr, code_memcpy, sizeof(code_memcpy)};
    exports["memcpy"] = memcpy_ex;

    Export _fmode_ex = {"_fmode", nullptr, nullptr, 0, msvcrt_env};
    exports["_fmode"] = _fmode_ex;

    Export _commode_ex = {"_commode", nullptr, nullptr, 0, msvcrt_env + 4};
    exports["_commode"] = _commode_ex;

    Export _wcmdln_ex = {"_wcmdln", nullptr, nullptr, 0, msvcrt_env + 0x10};
    exports["_wcmdln"] = _wcmdln_ex;

    Export _onexit_ex = {"_onexit", cb_msvcrt_onexit};
    exports["_onexit"] = _onexit_ex;

    Export malloc_ex = {"malloc", cb_msvcrt_malloc};
    exports["malloc"] = malloc_ex;

    Export free_ex = {"free", cb_msvcrt_free};
    exports["free"] = free_ex;

    Export operator_new_ex = {"??2@YAPAXI@Z", cb_msvcrt_malloc};
    exports["??2@YAPAXI@Z"] = operator_new_ex;

    Export operator_delete_ex = {"??3@YAXPAX@Z", cb_msvcrt_free};
    exports["??3@YAXPAX@Z"] = operator_delete_ex;

    Export operator_delete_arr_ex = {"??_V@YAXPAX@Z", cb_msvcrt_free};
    exports["??_V@YAXPAX@Z"] = operator_delete_arr_ex;

    Export _amsg_exit_ex = {"_amsg_exit", cb_msvcrt_amsg_exit};
    exports["_amsg_exit"] = _amsg_exit_ex;
}