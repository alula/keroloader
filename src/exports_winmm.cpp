#include <cstdint>
#include <ctime>
#include <cstring>
#include <string>
#include "common.h"
#include "exports.h"

static uint8_t code_ret_clean4[] = {0xc2, 0x04, 0x00}; // ret 4

static void cb_winmm_timeGetTime(uc_engine *uc, uint32_t esp)
{
    struct timespec time_now;
    uint32_t time_value;
    uint32_t return_addr;

    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    esp += 4;

    clock_gettime(CLOCK_MONOTONIC, &time_now);
    time_value = time_now.tv_sec * 1000 + (time_now.tv_nsec / 1000000);

    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &time_value));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

void install_winmm_exports(uc_engine *uc)
{
    Export timeBeginPeriod_ex = {"timeBeginPeriod", nullptr, code_ret_clean4, sizeof(code_ret_clean4)};
    exports["timeBeginPeriod"] = timeBeginPeriod_ex;

    Export timeEndPeriod_ex = {"timeEndPeriod", nullptr, code_ret_clean4, sizeof(code_ret_clean4)};
    exports["timeEndPeriod"] = timeEndPeriod_ex;

    Export timeGetTime_ex = {"timeGetTime", cb_winmm_timeGetTime};
    exports["timeGetTime"] = timeGetTime_ex;
}