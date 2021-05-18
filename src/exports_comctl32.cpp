#include <cstdint>
#include <ctime>
#include <cstring>
#include <string>
#include "common.h"
#include "exports.h"

static uint8_t code_ret[] = {0xc3};

void install_comctl32_exports(uc_engine *uc)
{
    Export InitCommonControls_ex = {"InitCommonControls", nullptr, code_ret, sizeof(code_ret)};
    exports["InitCommonControls"] = InitCommonControls_ex;
    exports["ORDINAL_COMCTL32.DLL_17"] = InitCommonControls_ex;
}