#include <cstdint>
#include <ctime>
#include <cstring>
#include <string>
#include "common.h"
#include "exports.h"

static void cb_steam_api_SteamAPI_Init(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t ret = 0;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));

    esp += 4;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

void install_steam_api_exports(uc_engine *uc)
{
    Export SteamAPI_Init_ex = {"SteamAPI_Init", cb_steam_api_SteamAPI_Init};
    exports["SteamAPI_Init"] = SteamAPI_Init_ex;
}