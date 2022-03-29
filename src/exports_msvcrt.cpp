#include <cstdint>
#include <cstddef>
#include <cstring>
#include <ctime>
#include "common.h"
#include "exports.h"

struct win_tm
{
    int tm_sec;
    int tm_min;
    int tm_hour;
    int tm_mday;
    int tm_mon;
    int tm_year;
    int tm_wday;
    int tm_yday;
    int tm_isdst;
};

union msvcrt_mem
{
    struct
    {
        win_tm timer;
        uint64_t timestamp;
    } data;
    char align[4096];
};

constexpr uint32_t msvcrt_mem_base = 0xf0100000;
static msvcrt_mem mem;

static_assert(sizeof(time_t) == 8, "time_t is not 64-bit!");

struct double_bits
{
    uint64_t signif : 52;
    unsigned exp : 11;
    unsigned sign : 1;
};

typedef struct
{
    uint64_t signif;
    union
    {
        uint16_t signExp;
        struct
        {
            unsigned int exp : 15;
            unsigned int sign : 1;
        } raw;
    } x;
} float80;

constexpr float80 F80_NAN = {.signif = 0xc000000000000000, .x = {.raw = {.exp = 0x7fff, .sign = 0}}};
constexpr float80 F80_INF = {.signif = 0x8000000000000000, .x = {.raw = {.exp = 0x7fff, .sign = 0}}};

float80 f80_from_double(double d)
{
    struct double_bits db;
    memcpy(&db, &d, sizeof(db));
    float80 f;

    if (db.exp == 0x7ff)
        f.x.raw.exp = 0x7fff;
    else if (db.exp == 0)
        f.x.raw.exp = db.signif == 0 ? 0 : (1 - 0x3ff + 0x3fff);
    else
        f.x.raw.exp = ((int)db.exp - 0x3ff) + 0x3fff;

    f.signif = db.signif << 11;
    if (db.exp != 0)
        f.signif |= (1ull << 63);
    f.x.raw.sign = db.sign;

    if (f.x.raw.exp == 0)
        return f;
    int shift = __builtin_clzl(f.signif);
    if (f.signif == 0)
        shift = 64;
    if (f.x.raw.exp - shift < 1)
    {
        int shift = f.x.raw.exp - 1;
        f.signif <<= shift;
        f.x.raw.exp -= shift;
        f.x.raw.exp = 0;
        return f;
    }

    f.signif <<= shift;
    f.x.raw.exp -= shift;
    
    return f;
}

static void cb_msvcrt_difftime64(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint64_t time1;
    uint64_t time2;
    double ret = 0.0;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &time1, 8));
    uc_assert(uc_mem_read(uc, esp + 12, &time2, 8));

    ret = difftime(time1, time2);
    printf("diff time: %ld %ld %f\n", time1, time2, ret);
    float80 value = f80_from_double(ret);

    esp += 4;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_ST0, &value));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_msvcrt_mktime64(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t lp_timer;
    uint32_t ret_hi = 0;
    uint32_t ret_lo = 0;
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &lp_timer, 4));

    if (lp_timer != 0)
    {
        win_tm wtime;
        tm t;
        uc_assert(uc_mem_read(uc, lp_timer, &wtime, sizeof(win_tm)));

        t.tm_sec = wtime.tm_sec;
        t.tm_min = wtime.tm_min;
        t.tm_hour = wtime.tm_hour;
        t.tm_mday = wtime.tm_mday;
        t.tm_mon = wtime.tm_mon;
        t.tm_year = wtime.tm_year;
        t.tm_wday = wtime.tm_wday;
        t.tm_yday = wtime.tm_yday;
        t.tm_isdst = wtime.tm_isdst;

        time_t out = mktime(&t);
        ret_hi = (out >> 32);
        ret_lo = (out & 0xffffffff);
        //uc_assert(uc_mem_write(uc, lp_timer, &t, 8));
    }

    esp += 4;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret_lo));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EDX, &ret_hi));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_msvcrt_time64(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t lp_timer;
    uint32_t ret = msvcrt_mem_base + offsetof(msvcrt_mem, data.timestamp);
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &lp_timer, 4));

    time_t t;
    time(&t);

    mem.data.timestamp = t;

    if (lp_timer != 0)
    {
        uc_assert(uc_mem_write(uc, lp_timer, &t, 8));
    }

    esp += 4;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_msvcrt_localtime64(uc_engine *uc, uint32_t esp)
{
    uint32_t return_addr;
    uint32_t lp_timer;
    uint32_t ret = msvcrt_mem_base + offsetof(msvcrt_mem, data.timer);
    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &lp_timer, 4));

    time_t timer;
    uc_assert(uc_mem_read(uc, lp_timer, &timer, 8));

    struct tm *t = localtime(&timer);
    mem.data.timer.tm_sec = t->tm_sec;
    mem.data.timer.tm_min = t->tm_min;
    mem.data.timer.tm_hour = t->tm_hour;
    mem.data.timer.tm_mday = t->tm_mday;
    mem.data.timer.tm_mon = t->tm_mon;
    mem.data.timer.tm_year = t->tm_year;
    mem.data.timer.tm_wday = t->tm_wday;
    mem.data.timer.tm_yday = t->tm_yday;
    mem.data.timer.tm_isdst = t->tm_isdst;
    if (lp_timer != 0)
    {
        uc_assert(uc_mem_write(uc, lp_timer, &timer, 8));
    }

    esp += 4;
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

void install_msvcrt_exports(uc_engine *uc)
{
    uc_assert(uc_mem_map_ptr(uc, msvcrt_mem_base, sizeof(msvcrt_mem), UC_PROT_READ | UC_PROT_WRITE, &mem));

    Export _difftime64_ex = {"_difftime64", cb_msvcrt_difftime64};
    exports["_difftime64"] = _difftime64_ex;

    Export _mktime64_ex = {"_mktime64", cb_msvcrt_mktime64};
    exports["_mktime64"] = _mktime64_ex;

    Export _time64_ex = {"_time64", cb_msvcrt_time64};
    exports["_time64"] = _time64_ex;

    Export _localtime64_ex = {"_localtime64", cb_msvcrt_localtime64};
    exports["_localtime64"] = _localtime64_ex;
}