#include <cstdint>
#include <ctime>
#include <cstring>
#include <string>
#include "common.h"
#include "exports.h"

static uint8_t code_ret_clean4[] = {0xc2, 0x04, 0x00}; // ret 4

void install_winmm_exports(uc_engine *uc)
{
    Export timeBeginPeriod_ex = {"timeBeginPeriod", nullptr, code_ret_clean4, sizeof(code_ret_clean4)};
    exports["timeBeginPeriod"] = timeBeginPeriod_ex;
}