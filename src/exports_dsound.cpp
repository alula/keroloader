#include <cstdint>
#include <cstring>
#include <string>
#include <mutex>
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
    bool playing = false;
    bool looping = false;
    float position = 0.0;
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
bool sound_initialized = false;

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
            break;
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

    sound_initialized = true;
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
    uint32_t self;
    uint32_t flags;
    uint32_t ret = 0;
    uint32_t return_addr;

    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &self, 4));
    uc_assert(uc_mem_read(uc, esp + 12, &flags, 4));

    if (self != 0)
    {
        auto dsb = reinterpret_cast<DSB *>(uintptr_t(&mem) + uintptr_t(self) - uintptr_t(dsound_mem_base));
        if (dsb->used)
        {
            dsb->playing = true;
            if ((flags & 1) != 0)
                dsb->looping = true;
        }
    }
    esp += 20;

    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_dsound_IDirectSoundBuffer_Stop(uc_engine *uc, uint32_t esp)
{
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
    uint32_t self;
    uint32_t new_pos;
    uint32_t ret = 0;
    uint32_t return_addr;

    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &self, 4));
    uc_assert(uc_mem_read(uc, esp + 8, &new_pos, 4));

    if (self != 0)
    {
        auto dsb = reinterpret_cast<DSB *>(uintptr_t(&mem) + uintptr_t(self) - uintptr_t(dsound_mem_base));
        if (dsb->used)
        {
            if (new_pos == 0)
            {
                dsb->position = 0;
            }
            else
            {
                dsb->position = new_pos * (44100.0f / 44100.0f);
            }
        }
    }

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

static std::mutex audioMutex;

static int16_t audio_buf[44100];

void dsound_stream_cb(float *buffer, int num_frames, int num_channels)
{
    int to_render = num_frames;
    int index = 0;

    bool lock = audioMutex.try_lock();
    if (!lock)
        return;

    // if (pxtone_playing)
    // {
    //     if (pxtone.Moo(audio_buf, num_frames * 2 * sizeof(uint16_t)))
    //     {
    //         if (num_channels == 2)
    //         {
    //             for (int i = 0; i < num_frames * 2; i++)
    //             {
    //                 buffer[index++] = float(audio_buf[i]) / 32768.0f;
    //             }
    //         }
    //         else
    //         {
    //             for (int i = 0; i < num_frames; i++)
    //             {
    //                 buffer[index++] = float(audio_buf[i * 2 + 1]) / 32768.0f;
    //             }
    //         }
    //     }
    // }
    // else
    {
        for (int i = 0; i < num_frames * num_channels; i++)
        {
            buffer[i] = 0.0f;
        }
    }

    constexpr float phase = 44100.0f / 44100.0f; // todo use sample rate info from dsound buffers
    constexpr float s16tof = 1.0f / 32768.0f;

    for (int idx = 0; idx < 512; idx++)
    {
        auto &buf = mem.sound_buffers[idx];
        if (!buf.used || !buf.playing)
            continue;

        for (int i = 0; i < num_frames; i++)
        {
            int pos_int = (int)buf.position;
            int length = buf.buf_size / 2;
            if (pos_int > length)
            {
                if (buf.looping)
                {
                    buf.position = 0;
                    pos_int = 0;
                }
                else
                {
                    buf.playing = false;
                    break;
                }
            }

            buf.position += phase;
            if (num_channels == 2)
            {
                buffer[i * 2] += (((int16_t *)buf.hostbuf)[pos_int] ^ 0x0000) * s16tof;
                buffer[i * 2 + 1] += (((int16_t *)buf.hostbuf)[pos_int] ^ 0x0000) * s16tof;
            }
            else
            {
                buffer[i] += (((int16_t *)buf.hostbuf)[pos_int] ^ 0x0000) * s16tof;
            }
        }
    }

    audioMutex.unlock();
}

void install_dsound_exports(uc_engine *uc)
{
    uc_assert(uc_mem_map_ptr(uc, dsound_mem_base, align_address(sizeof(dsound_mem)), UC_PROT_READ | UC_PROT_WRITE, &mem));
    mem.Init(uc);
    // pxtnERR pxtn_err = pxtnERR_VOID;
    // pxtn_err = pxtone.init();
    // if (pxtn_err == pxtnOK)
    // {
    //     pxtone_initialized = true;
    //     pxtone.set_destination_quality(2, 44100);
    // }
    // else
    // {
    //     logf("Failed to initialize pxtone.\n");
    // }

    // pxtone_play_handler = add_syscall(uc, thunk_cbs.size(), cb_pxtone_playbgm);

    Export DirectSoundCreate_ex = {"DirectSoundCreate", cb_dsound_DirectSoundCreate};
    exports["DirectSoundCreate"] = DirectSoundCreate_ex;

    Export DirectSoundCreate_ex2 = {"ORDINAL_DSOUND.DLL_1", cb_dsound_DirectSoundCreate};
    exports["ORDINAL_DSOUND.DLL_1"] = DirectSoundCreate_ex2;
}