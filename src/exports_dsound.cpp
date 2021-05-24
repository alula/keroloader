#include <cstdint>
#include <cstring>
#include <string>
#include "common.h"
#include "exports.h"

struct IDirectSound
{
    uint32_t vtbl;
};

struct IDirectSoundVtable
{
    uint32_t QueryInterface = 0xdead0601;
    uint32_t AddRef = 0xdead0602;
    uint32_t Release = 0xdead0603;
    uint32_t CreateSoundBuffer = 0xdead0604;
    uint32_t GetCaps = 0xdead0605;
    uint32_t DuplicateSoundBuffer = 0xdead0606;
    uint32_t SetCooperativeLevel = 0xdead0607;
    uint32_t Compact = 0xdead0608;
    uint32_t GetSpeakerConfig = 0xdead0609;
    uint32_t SetSpeakerConfig = 0xdead060a;
    uint32_t Initialize = 0xdead060b;

    void Init(uc_engine *uc);
};

struct IDirectSoundBuffer
{
    uint32_t vtbl;
};

struct IDirectSoundBufferVtable
{
    uint32_t QueryInterface = 0xdead0701;
    uint32_t AddRef = 0xdead0702;
    uint32_t Release = 0xdead0703;
    uint32_t GetCaps = 0xdead0704;
    uint32_t GetCurrentPosition = 0xdead0705;
    uint32_t GetFormat = 0xdead0706;
    uint32_t GetVolume = 0xdead0707;
    uint32_t GetPan = 0xdead0708;
    uint32_t GetFrequency = 0xdead0709;
    uint32_t GetStatus = 0xdead070a;
    uint32_t Initialize = 0xdead070b;
    uint32_t Lock = 0xdead070c;
    uint32_t Play = 0xdead070d;
    uint32_t SetCurrentPosition = 0xdead070e;
    uint32_t SetFormat = 0xdead070f;
    uint32_t SetVolume = 0xdead0710;
    uint32_t SetPan = 0xdead0711;
    uint32_t SetFrequency = 0xdead0712;
    uint32_t Stop = 0xdead0713;
    uint32_t Unlock = 0xdead0714;
    uint32_t Restore = 0xdead0715;

    void Init(uc_engine *uc);
};

struct DSB
{
    IDirectSoundBuffer data;
    IDirectSoundBufferVtable vtbl;
    bool used = false;
    uint32_t buf;
    uint32_t buf_size;
    void *hostbuf;
};

struct dsound_mem
{
    IDirectSound dsound;
    IDirectSoundVtable dsound_vtable;
    DSB sound_buffers[512];

    void Init(uc_engine *uc);
};

constexpr uint32_t dsound_mem_base = 0xf0400000;
static dsound_mem mem;

static void cb_dsound_DirectSoundCreate(uc_engine *uc, uint32_t esp)
{
    uint32_t dsound_buf;
    uint32_t ret = 0;
    uint32_t return_addr;

    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 8, &dsound_buf, 4));

    uint32_t addr = dsound_mem_base + offsetof(dsound_mem, dsound);
    uc_assert(uc_mem_write(uc, dsound_buf, &addr, 4));
    esp += 16;

    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_dsound_IDirectSound_SetCooperativeLevel(uc_engine *uc, uint32_t esp)
{
    uint32_t ret = 0;
    uint32_t return_addr;

    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    esp += 16;

    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_dsound_IDirectSound_CreateSoundBuffer(uc_engine *uc, uint32_t esp)
{
    uint32_t dsb;
    uint32_t ret = 1;
    uint32_t return_addr;

    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 12, &dsb, 4));
    for (int i = 0; i < 512; i++)
    {
        if (!mem.sound_buffers[i].used)
        {
            uint32_t addr = dsound_mem_base + offsetof(dsound_mem, sound_buffers) + i * sizeof(DSB) + offsetof(DSB, data);
            uc_assert(uc_mem_write(uc, dsb, &addr, 4));
            mem.sound_buffers[i].used = true;
            ret = 0;
        }
    }

    esp += 20;

    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_dsound_IDirectSoundBuffer_Lock(uc_engine *uc, uint32_t esp)
{
    uint32_t self;
    uint32_t byte_count;
    uint32_t lp_buffer;
    uint32_t lp_buffer_size;
    uint32_t lp_buffer_size2;
    uint32_t ret = 0;
    uint32_t return_addr;
    uintptr_t emu_buf;

    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &self, 4));
    uc_assert(uc_mem_read(uc, esp + 12, &byte_count, 4));
    uc_assert(uc_mem_read(uc, esp + 16, &lp_buffer, 4));
    uc_assert(uc_mem_read(uc, esp + 20, &lp_buffer_size, 4));
    uc_assert(uc_mem_read(uc, esp + 28, &lp_buffer_size2, 4));
    esp += 36;

    auto dsb = reinterpret_cast<DSB *>(uintptr_t(&mem) + uintptr_t(self) - uintptr_t(dsound_mem_base));
    if (dsb->hostbuf != nullptr)
    {
        kernel32_host_free(dsb->hostbuf);
    }

    dsb->hostbuf = kernel32_host_malloc(&emu_buf, byte_count);
    dsb->buf = uint32_t(emu_buf);
    dsb->buf_size = byte_count;

    if (lp_buffer != 0)
        uc_assert(uc_mem_write(uc, lp_buffer, &dsb->buf, 4));

    if (lp_buffer_size != 0)
        uc_assert(uc_mem_write(uc, lp_buffer_size, &byte_count, 4));

    byte_count = 0;
    if (lp_buffer_size2 != 0)
        uc_assert(uc_mem_write(uc, lp_buffer_size2, &byte_count, 4));

    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_dsound_IDirectSoundBuffer_Unlock(uc_engine *uc, uint32_t esp)
{
    uint32_t dsb;
    uint32_t ret = 0;
    uint32_t return_addr;

    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    esp += 24;

    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_dsound_IDirectSoundBuffer_Play(uc_engine *uc, uint32_t esp)
{
    uint32_t dsb;
    uint32_t ret = 0;
    uint32_t return_addr;

    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    esp += 20;

    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_dsound_IDirectSoundBuffer_Stop(uc_engine *uc, uint32_t esp)
{
    uint32_t dsb;
    uint32_t ret = 0;
    uint32_t return_addr;

    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    esp += 8;

    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_dsound_IDirectSoundBuffer_SetCurrentPosition(uc_engine *uc, uint32_t esp)
{
    uint32_t dsb;
    uint32_t ret = 0;
    uint32_t return_addr;

    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    esp += 12;

    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_dsound_IDirectSoundBuffer_Release(uc_engine *uc, uint32_t esp)
{
    uint32_t self;
    uint32_t ret = 0;
    uint32_t return_addr;

    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &self, 4));
    esp += 8;

    auto dsb = reinterpret_cast<DSB *>(uintptr_t(&mem) + uintptr_t(self) - uintptr_t(dsound_mem_base));
    if (dsb->hostbuf != nullptr)
    {
        kernel32_host_free(dsb->hostbuf);
        dsb->hostbuf = nullptr;
        dsb->buf = 0;
        dsb->buf_size = 0;
    }
    dsb->used = false;

    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

void dsound_mem::Init(uc_engine *uc)
{
    mem.dsound.vtbl = dsound_mem_base + offsetof(dsound_mem, dsound_vtable);
    mem.dsound_vtable.Init(uc);

    for (int i = 0; i < 512; i++)
    {
        mem.sound_buffers[i].data.vtbl = dsound_mem_base + offsetof(dsound_mem, sound_buffers) + i * sizeof(DSB) + offsetof(DSB, vtbl);
        mem.sound_buffers[i].vtbl.Init(uc);
    }
}

void IDirectSoundVtable::Init(uc_engine *uc)
{
    SetCooperativeLevel = add_syscall(uc, thunk_cbs.size(), cb_dsound_IDirectSound_SetCooperativeLevel);
    CreateSoundBuffer = add_syscall(uc, thunk_cbs.size(), cb_dsound_IDirectSound_CreateSoundBuffer);
}

void IDirectSoundBufferVtable::Init(uc_engine *uc)
{
    Release = add_syscall(uc, thunk_cbs.size(), cb_dsound_IDirectSoundBuffer_Release);
    Lock = add_syscall(uc, thunk_cbs.size(), cb_dsound_IDirectSoundBuffer_Lock);
    Unlock = add_syscall(uc, thunk_cbs.size(), cb_dsound_IDirectSoundBuffer_Unlock);
    Play = add_syscall(uc, thunk_cbs.size(), cb_dsound_IDirectSoundBuffer_Play);
    Stop = add_syscall(uc, thunk_cbs.size(), cb_dsound_IDirectSoundBuffer_Stop);
    SetCurrentPosition = add_syscall(uc, thunk_cbs.size(), cb_dsound_IDirectSoundBuffer_SetCurrentPosition);
}

void install_dsound_exports(uc_engine *uc)
{
    uc_assert(uc_mem_map_ptr(uc, dsound_mem_base, align_address(sizeof(dsound_mem)), UC_PROT_READ | UC_PROT_WRITE, &mem));
    mem.Init(uc);

    Export DirectSoundCreate_ex = {"DirectSoundCreate", cb_dsound_DirectSoundCreate};
    exports["DirectSoundCreate"] = DirectSoundCreate_ex;

    Export DirectSoundCreate_ex2 = {"ORDINAL_DSOUND.DLL_1", cb_dsound_DirectSoundCreate};
    exports["ORDINAL_DSOUND.DLL_1"] = DirectSoundCreate_ex2;
}