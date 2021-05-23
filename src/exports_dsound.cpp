#include <cstdint>
#include <cstring>
#include <string>
#include "common.h"
#include "exports.h"

struct dsound_mem
{
    char padding[2000];

    void Init(uc_engine *uc);
};

constexpr uint32_t dsound_mem_base = 0xf0300000;
static dsound_mem mem;

void dsound_mem::Init(uc_engine* uc) {
    
}

static void cb_dsound_DirectSoundCreate(uc_engine *uc, uint32_t esp)
{
    uint32_t ret = 0;
    uint32_t return_addr;

    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    esp += 4;


    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

void install_dsound_exports(uc_engine *uc)
{
    uc_assert(uc_mem_map_ptr(uc, dsound_mem_base, align_address(sizeof(dsound_mem)), UC_PROT_READ | UC_PROT_WRITE, &mem));
    mem.Init(uc);

    Export DirectSoundCreate_ex = {"DirectSoundCreate", cb_dsound_DirectSoundCreate};
    exports["DirectSoundCreate"] = DirectSoundCreate_ex;
}