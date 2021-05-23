#include <cstdint>
#include <ctime>
#include <cstring>
#include <string>
#include "common.h"
#include "exports.h"

#include "sokol/imconfig.h"
#include "sokol/sokol_app.h"

/*
PeekMessageW:
    mov eax, [DWORD PTR 0xf0300000]
    mov ecx, [DWORD PTR 0xf0300004]
    test eax, eax
    jz loopend
    test ecx, ecx
    jz loopend
    mov esi, 0xf0300008
loopp:
    push ecx
    push eax
    push [esi+12]
    push [esi+8]
    push [esi+4]
    push [esi]
    call eax
    pop eax
    pop ecx
    add esi, 16
    loop loopp
loopend:
    mov [DWORD PTR 0xf0300004], 0
    xor eax, eax
    ret 20
 */
static uint8_t code_dispatcher[] = {0xA1, 0x00, 0x00, 0x30, 0xF0, 0x8B, 0x0D, 0x04, 0x00, 0x30, 0xF0, 0x85, 0xC0, 0x74,
                                    0x1F, 0x85, 0xC9, 0x74, 0x1B, 0xBE, 0x08, 0x00, 0x30, 0xF0, 0x51, 0x50, 0xFF, 0x76,
                                    0x0C, 0xFF, 0x76, 0x08, 0xFF, 0x76, 0x04, 0xFF, 0x36, 0xFF, 0xD0, 0x58, 0x59, 0x83,
                                    0xC6, 0x10, 0xE2, 0xEA, 0xC7, 0x05, 0x04, 0x00, 0x30, 0xF0, 0x00, 0x00, 0x00, 0x00,
                                    0x31, 0xC0, 0xC2, 0x14, 0x00};

constexpr uint32_t user_mem_base = 0xf0300000;
struct wndproc_msg_t
{
    uint32_t hwnd;
    uint32_t msg;
    uint32_t lparam;
    uint32_t rparam;
};

union user32_mem_t
{
    struct
    {
        uint32_t wndproc_addr;
        uint32_t message_count;
        wndproc_msg_t messages[512];
    } data;
    char align[4096 * 3];
};

static user32_mem_t mem;

void push_window_message(uint32_t msg, uint32_t lparam, uint32_t rparam)
{
    if (mem.data.message_count == 512) return;

    uint32_t idx = mem.data.message_count++;
    mem.data.messages[idx].hwnd = 1;
    mem.data.messages[idx].msg = msg;
    mem.data.messages[idx].lparam = lparam;
    mem.data.messages[idx].rparam = rparam;
}

static void cb_user32_PeekMessageW(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t ret = 0;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));

    esp += 24;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_user32_PostMessageA(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t ret = 1;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));

    esp += 20;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_user32_GetClientRect(uc_engine *uc, uint32_t esp)
{
    uint32_t lp_rect;
    uint32_t return_addr;
    uint32_t ret = 0;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 8, &lp_rect, 4));

    if (lp_rect != 0)
    {
        uc_assert(uc_mem_write(uc, lp_rect, &ret, 4));
        uc_assert(uc_mem_write(uc, lp_rect + 4, &ret, 4));
        uc_assert(uc_mem_write(uc, lp_rect + 8, &window_width, 4));
        uc_assert(uc_mem_write(uc, lp_rect + 12, &window_height, 4));

        ret = 1;
    }

    esp += 12;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_user32_GetWindowRect(uc_engine *uc, uint32_t esp)
{
    uint32_t lp_rect;
    uint32_t return_addr;
    uint32_t ret = 0;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 8, &lp_rect, 4));

    if (lp_rect != 0)
    {
        uc_assert(uc_mem_write(uc, lp_rect, &ret, 4));
        uc_assert(uc_mem_write(uc, lp_rect + 4, &ret, 4));
        uc_assert(uc_mem_write(uc, lp_rect + 8, &window_width, 4));
        uc_assert(uc_mem_write(uc, lp_rect + 12, &window_height, 4));

        ret = 1;
    }

    esp += 12;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_user32_GetParent(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t ret = 0;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));

    esp += 12;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_user32_GetSystemMenu(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t ret = 0;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));

    esp += 12;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_user32_GetMenuItemCount(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t ret = 1;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));

    esp += 8;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_user32_GetMenuItemInfoA(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t ret = 0;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));

    esp += 20;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}


static void cb_user32_GetMenuItemInfoW(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t ret = 0;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));

    esp += 20;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_user32_ImmDisableIME(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t ret = 1;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));

    esp += 8;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_user32_LoadIconW(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t ret = 1;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));

    logf("LoadIconW() stub\n");

    esp += 12;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_user32_LoadCursorW(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t ret = 1;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));

    logf("LoadCursorW() stub\n");

    esp += 12;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_user32_CreateFontW(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t ret = 1;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));

    logf("CreateFontW() stub\n");

    esp += 60;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_user32_RegisterClassExW(uc_engine *uc, uint32_t esp)
{
    uint32_t desc;
    uint32_t return_addr;
    uint32_t ret;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &desc, 4));

    if (desc != 0)
    {
        uc_assert(uc_mem_read(uc, desc + 8, &mem.data.wndproc_addr, 4));
        ret = 1;
    }

    esp += 8;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_user32_ShowWindow(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t ret = 1;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));

    esp += 12;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_user32_DragAcceptFiles(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));

    esp += 12;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_user32_SetWindowPos(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t ret = 1;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));

    logf("SetWindowPos() stub\n");

    esp += 32;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_user32_SetWindowsHookExA(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    /*uint32_t hook_type;
    uint32_t callback;
    uint32_t module_handle;
    uint32_t thread_id;*/
    uint32_t ret = 0x1400;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    /*uc_assert(uc_mem_read(uc, esp + 4, &hook_type, 4));
    uc_assert(uc_mem_read(uc, esp + 8, &callback, 4));
    uc_assert(uc_mem_read(uc, esp + 12, &module_handle, 4));
    uc_assert(uc_mem_read(uc, esp + 16, &thread_id, 4));*/

    esp += 20;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_user32_SetWindowsHookExW(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    /*uint32_t hook_type;
    uint32_t callback;
    uint32_t module_handle;
    uint32_t thread_id;*/
    uint32_t ret = 0x1400;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    /*uc_assert(uc_mem_read(uc, esp + 4, &hook_type, 4));
    uc_assert(uc_mem_read(uc, esp + 8, &callback, 4));
    uc_assert(uc_mem_read(uc, esp + 12, &module_handle, 4));
    uc_assert(uc_mem_read(uc, esp + 16, &thread_id, 4));*/

    esp += 20;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_user32_CreateWindowExA(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t name_buf;
    uint32_t ret = 1;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 12, &name_buf, 4));

    if (name_buf != 0)
    {
        auto name = read_string(uc, name_buf);
        sapp_set_window_title(name.c_str());
        push_window_message(1, 0, 0);
    }

    esp += 52;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_user32_CreateWindowExW(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t name_buf;
    uint32_t ret = 1;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 12, &name_buf, 4));

    if (name_buf != 0)
    {
        auto name = to_utf8string(read_u16string(uc, name_buf));
        sapp_set_window_title(name.c_str());
        push_window_message(1, 0, 0);
    }

    esp += 52;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_user32_SystemParametersInfoW(uc_engine *uc, uint32_t esp)
{
    uint32_t param;
    uint32_t tgt;
    uint32_t return_addr;
    uint32_t tmp;
    uint32_t ret = 0;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &param, 4));
    uc_assert(uc_mem_read(uc, esp + 12, &tgt, 4));

    switch (param)
    {
    case 0x30: // SPI_GETWORKAREA
        ret = 1;
        tmp = 570;
        uc_assert(uc_mem_write(uc, tgt + 8, &tmp, 4));
        tmp = 320;
        uc_assert(uc_mem_write(uc, tgt + 12, &tmp, 4));
        break;
    default:
        logf("Unknown system parameter: %#x\n", param);
        break;
    }

    esp += 20;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_user32_GetSystemMetrics(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t metrics;
    uint32_t ret = 0;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &metrics, 4));

    switch (metrics)
    {
    case 0:  // SM_CXSCREEN
    case 61: // SM_CXMAXIMIZED
        ret = 570;
        break;
    case 1:  // SM_CYSCREEN
    case 62: // SM_CYMAXIMIZED
        ret = 320;
        break;
    case 28: // SM_CXMIN
    case 29: // SM_CYMIN
        ret = 64;
        break;
    default:
        logf("Unknown system metrics: %u\n", metrics);
        break;
    }

    esp += 8;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_user32_MessageBoxA(uc_engine *uc, uint32_t esp)
{
    char msgbox_title[2048] = {0};
    char msgbox_message[4096] = {0};
    uint32_t return_addr;
    uint32_t hwnd;
    uint32_t message;
    uint32_t title;
    uint32_t icon;

    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &hwnd, 4));
    uc_assert(uc_mem_read(uc, esp + 8, &message, 4));
    uc_assert(uc_mem_read(uc, esp + 12, &title, 4));
    uc_assert(uc_mem_read(uc, esp + 16, &icon, 4));

    printf("MessageBoxA(%#010x, %#010x, %#010x, %#010x)\n", hwnd, message, title, icon);

    uc_assert(uc_mem_read(uc, title, &msgbox_title, sizeof(msgbox_title)));
    uc_assert(uc_mem_read(uc, message, &msgbox_message, sizeof(msgbox_message)));
    strncpy(msgbox_title_txt, msgbox_title, sizeof(msgbox_title_txt));
    strncpy(msgbox_message_txt, msgbox_message, sizeof(msgbox_message_txt));

    esp += 16;

    uc_assert(uc_mem_write(uc, esp, &return_addr, 4));
    hwnd = 1;
    uc_assert(uc_mem_write(uc, emu_spinlock_lock, &hwnd, 4));

    logf("lock addr = %#010x thunk = %#010x\n", emu_spinlock_lock, emu_spinlock_thunk);

    uc_assert(uc_emu_stop(uc));
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &emu_spinlock_thunk));
}

static void cb_test(uc_engine *uc, uint32_t esp)
{
    uint32_t par1;
    uint32_t par2;
    uint32_t par3;
    uint32_t par4;
    uint32_t return_addr;
    uint32_t ret = 0;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &par1, 4));
    uc_assert(uc_mem_read(uc, esp + 8, &par2, 4));
    uc_assert(uc_mem_read(uc, esp + 12, &par3, 4));
    uc_assert(uc_mem_read(uc, esp + 16, &par4, 4));

    logf("Callback test %#010x %#010x %#010x %#010x\n", par1, par2, par3, par4);

    esp += 20;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

void install_user32_exports(uc_engine *uc)
{
    // mem.data.wndproc_addr = add_syscall(uc, thunk_cbs.size(), cb_test);
    mem.data.wndproc_addr = 0;
    mem.data.message_count = 0;
    uc_assert(uc_mem_map_ptr(uc, user_mem_base, align_address(sizeof(user32_mem_t)), UC_PROT_READ | UC_PROT_WRITE, &mem));

    // Export PeekMessageW_ex = {"PeekMessageW", cb_user32_PeekMessageW};
    Export PeekMessageW_ex = {"PeekMessageW", nullptr, code_dispatcher, sizeof(code_dispatcher)};
    exports["PeekMessageW"] = PeekMessageW_ex;

    Export PeekMessageA_ex = {"PeekMessageA", nullptr, code_dispatcher, sizeof(code_dispatcher)};
    exports["PeekMessageA"] = PeekMessageA_ex;

    Export PostMessageA_ex = {"PostMessageA", cb_user32_PostMessageA};
    exports["PostMessageA"] = PostMessageA_ex;

    Export GetClientRect_ex = {"GetClientRect", cb_user32_GetClientRect};
    exports["GetClientRect"] = GetClientRect_ex;

    Export GetWindowRect_ex = {"GetWindowRect", cb_user32_GetWindowRect};
    exports["GetWindowRect"] = GetWindowRect_ex;

    Export GetParent_ex = {"GetParent", cb_user32_GetParent};
    exports["GetParent"] = GetParent_ex;

    Export GetSystemMenu_ex = {"GetSystemMenu", cb_user32_GetSystemMenu};
    exports["GetSystemMenu"] = GetSystemMenu_ex;

    Export GetMenuItemCount_ex = {"GetMenuItemCount", cb_user32_GetMenuItemCount};
    exports["GetMenuItemCount"] = GetMenuItemCount_ex;

    Export GetMenuItemInfoA_ex = {"GetMenuItemInfoA", cb_user32_GetMenuItemInfoA};
    exports["GetMenuItemInfoA"] = GetMenuItemInfoA_ex;

    Export GetMenuItemInfoW_ex = {"GetMenuItemInfoW", cb_user32_GetMenuItemInfoW};
    exports["GetMenuItemInfoW"] = GetMenuItemInfoW_ex;

    Export ImmDisableIME_ex = {"ImmDisableIME", cb_user32_ImmDisableIME};
    exports["ImmDisableIME"] = ImmDisableIME_ex;

    Export LoadIconA_ex = {"LoadIconA", cb_user32_LoadIconW};
    exports["LoadIconA"] = LoadIconA_ex;

    Export LoadCursorA_ex = {"LoadCursorA", cb_user32_LoadCursorW};
    exports["LoadCursorA"] = LoadCursorA_ex;

    Export CreateFontA_ex = {"CreateFontA", cb_user32_CreateFontW};
    exports["CreateFontA"] = CreateFontA_ex;

    Export RegisterClassExA_ex = {"RegisterClassExA", cb_user32_RegisterClassExW};
    exports["RegisterClassExA"] = RegisterClassExA_ex;

    Export LoadIconW_ex = {"LoadIconW", cb_user32_LoadIconW};
    exports["LoadIconW"] = LoadIconW_ex;

    Export LoadCursorW_ex = {"LoadCursorW", cb_user32_LoadCursorW};
    exports["LoadCursorW"] = LoadCursorW_ex;

    Export CreateFontW_ex = {"CreateFontW", cb_user32_CreateFontW};
    exports["CreateFontW"] = CreateFontW_ex;

    Export RegisterClassExW_ex = {"RegisterClassExW", cb_user32_RegisterClassExW};
    exports["RegisterClassExW"] = RegisterClassExW_ex;

    Export ShowWindow_ex = {"ShowWindow", cb_user32_ShowWindow};
    exports["ShowWindow"] = ShowWindow_ex;

    Export DragAcceptFiles_ex = {"DragAcceptFiles", cb_user32_DragAcceptFiles};
    exports["DragAcceptFiles"] = DragAcceptFiles_ex;

    Export SetWindowPos_ex = {"SetWindowPos", cb_user32_SetWindowPos};
    exports["SetWindowPos"] = SetWindowPos_ex;

    Export SetWindowsHookExA_ex = {"SetWindowsHookExA", cb_user32_SetWindowsHookExA};
    exports["SetWindowsHookExA"] = SetWindowsHookExA_ex;

    Export SetWindowsHookExW_ex = {"SetWindowsHookExW", cb_user32_SetWindowsHookExW};
    exports["SetWindowsHookExW"] = SetWindowsHookExW_ex;

    Export CreateWindowExA_ex = {"CreateWindowExA", cb_user32_CreateWindowExA};
    exports["CreateWindowExA"] = CreateWindowExA_ex;

    Export CreateWindowExW_ex = {"CreateWindowExW", cb_user32_CreateWindowExW};
    exports["CreateWindowExW"] = CreateWindowExW_ex;

    Export SystemParametersInfoA_ex = {"SystemParametersInfoA", cb_user32_SystemParametersInfoW};
    exports["SystemParametersInfoA"] = SystemParametersInfoA_ex;

    Export SystemParametersInfoW_ex = {"SystemParametersInfoW", cb_user32_SystemParametersInfoW};
    exports["SystemParametersInfoW"] = SystemParametersInfoW_ex;

    Export GetSystemMetrics_ex = {"GetSystemMetrics", cb_user32_GetSystemMetrics};
    exports["GetSystemMetrics"] = GetSystemMetrics_ex;

    Export MessageBoxA_ex = {"MessageBoxA", cb_user32_MessageBoxA};
    exports["MessageBoxA"] = MessageBoxA_ex;
}