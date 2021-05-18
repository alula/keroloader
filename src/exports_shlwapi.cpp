#include <cstdint>
#include <ctime>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <string>
#include "common.h"
#include "exports.h"

static void cb_shlwapi_PathIsDirectoryW(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t path_buf;
    uint32_t ret = 0;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &path_buf, 4));

    if (path_buf != 0)
    {
        const auto str = read_u16string(uc, path_buf);
        const auto path = to_unix_path(str);

        std::error_code ec;
        if (std::filesystem::is_directory(path, ec))
        {
            ret = 1;
        }
        else
        {
            ret = 0;
        }
    }

    esp += 8;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_shlwapi_PathRemoveFileSpecW(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t path_buf;
    uint32_t ret = 0;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &path_buf, 4));

    if (path_buf != 0)
    {
        auto str = read_u16string(uc, path_buf);
        int indexof = 0;
        for (int i = 0; i < str.size(); i++)
        {
            if (str[i] == u'\\')
                indexof = i;
        }

        if (indexof != 0 && indexof != (str.size() - 1))
        {
            ret = 1;
            const uint16_t zero = 0;
            uc_assert(uc_mem_write(uc, path_buf + indexof * 2, &zero, 2));
        }
    }

    esp += 8;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

void install_shlwapi_exports(uc_engine *uc)
{
    Export PathIsDirectoryW_ex = {"PathIsDirectoryW", cb_shlwapi_PathIsDirectoryW};
    exports["PathIsDirectoryW"] = PathIsDirectoryW_ex;

    Export PathRemoveFileSpecW_ex = {"PathRemoveFileSpecW", cb_shlwapi_PathRemoveFileSpecW};
    exports["PathRemoveFileSpecW"] = PathRemoveFileSpecW_ex;
}