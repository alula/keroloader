#include <cstdint>
#include <ctime>
#include <cstring>
#include <string>
#include "common.h"
#include "exports.h"

static void cb_user32_SetWindowsHookExW(uc_engine *uc, uint32_t esp)
{

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

    printf("%s %s\n", msgbox_title_txt, msgbox_message_txt);
    esp += 16;

    uc_assert(uc_mem_write(uc, esp, &return_addr, 4));
    hwnd = 1;
    uc_assert(uc_mem_write(uc, emu_spinlock_lock, &hwnd, 4));
    
    logf("lock addr = %#010x thunk = %#010x\n", emu_spinlock_lock, emu_spinlock_thunk);

    uc_assert(uc_emu_stop(uc));
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &emu_spinlock_thunk));
}

void install_user32_exports(uc_engine *uc)
{
    Export MessageBoxA_ex = {"MessageBoxA", cb_user32_MessageBoxA};
    exports["MessageBoxA"] = MessageBoxA_ex;
}