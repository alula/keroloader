#include <cstdarg>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <unordered_map>
#include "pe-parse/parse.h"
#include <unicorn/unicorn.h>

#include "common.h"
#include "exports.h"

void logf(const char *fmt, ...)
{
    va_list list;
    va_start(list, fmt);
    vprintf(fmt, list);
    va_end(list);
}

#pragma pack(push, 1)
struct SegmentDescriptor
{
    union
    {
        struct
        {
#if __BYTE_ORDER == __LITTLE_ENDIAN
            unsigned short limit0;
            unsigned short base0;
            unsigned char base1;
            unsigned char type : 4;
            unsigned char system : 1; /* S flag */
            unsigned char dpl : 2;
            unsigned char present : 1; /* P flag */
            unsigned char limit1 : 4;
            unsigned char avail : 1;
            unsigned char is_64_code : 1;  /* L flag */
            unsigned char db : 1;          /* DB flag */
            unsigned char granularity : 1; /* G flag */
            unsigned char base2;
#else
            unsigned char base2;
            unsigned char granularity : 1; /* G flag */
            unsigned char db : 1;          /* DB flag */
            unsigned char is_64_code : 1;  /* L flag */
            unsigned char avail : 1;
            unsigned char limit1 : 4;
            unsigned char present : 1; /* P flag */
            unsigned char dpl : 2;
            unsigned char system : 1; /* S flag */
            unsigned char type : 4;
            unsigned char base1;
            unsigned short base0;
            unsigned short limit0;
#endif
        };
        uint64_t desc;
    };
};
#pragma pack(pop)

struct TIB32
{
    uint32_t seh_frame;
    uint32_t stack_base;
    uint32_t stack_top;
    uint32_t subsystem_tib;
    uint32_t fiber_data;
    uint32_t data_slot;
    uint32_t teb_linear;
};

#define SEGBASE(d) ((uint32_t)((((d).desc >> 16) & 0xffffff) | (((d).desc >> 32) & 0xff000000)))
#define SEGLIMIT(d) ((d).limit0 | (((unsigned int)(d).limit1) << 16))

static void init_descriptor(struct SegmentDescriptor *desc, uint32_t base, uint32_t limit, uint8_t is_code)
{
    desc->desc = 0; //clear the descriptor
    desc->base0 = base & 0xffff;
    desc->base1 = (base >> 16) & 0xff;
    desc->base2 = base >> 24;
    if (limit > 0xfffff)
    {
        //need Giant granularity
        limit >>= 12;
        desc->granularity = 1;
    }
    desc->limit0 = limit & 0xffff;
    desc->limit1 = limit >> 16;

    //some sane defaults
    desc->dpl = 3;
    desc->present = 1;
    desc->db = 1; //32 bit
    desc->type = is_code ? 0xb : 3;
    desc->system = 1; //code or data
}

uint32_t image_base = 0x00400000;
uint32_t heap_base = 0x01000000;
uint32_t gdt_base = 0x00300000;
uint32_t seg_base = 0xf0000000;
uint32_t stack_base = 0xc0000000;
uint32_t jit_base = 0xd0000000;

class ThreadCtx;

std::vector<void (*)(uc_engine *uc, uint32_t esp)> thunk_cbs;
static std::vector<ThreadCtx *> threads;
static uint32_t tid_counter = 1;
bool emu_failed = false;

uint32_t curr_thread = 0;
ThreadCtx *curr_thread_ref = nullptr;
void *heap = nullptr;
void *stack = nullptr;
uint32_t heap_size = 32 * 0x100000;
uint32_t stack_size = 0x100000;
uint32_t jit_last = jit_base;
uint32_t jit_size = 0;

uint32_t emu_spinlock_thunk = 0;
uint32_t emu_spinlock_lock = 0xf0000ff8;

std::unordered_map<std::string, uint32_t> import_cache;
static std::string export_log = "";

uint32_t last_error = 0;

/*
emu_spinlock:
    mov eax, DWORD PTR ds:0xf0000ff8
.lock:
    test eax, eax
    jne .lock
    ret
*/
static uint8_t emu_spinlock_code[] = {0xA1, 0xF8, 0x0F, 0x00, 0xF0, 0x85, 0xC0, 0x75, 0xFC, 0xC3};

peparse::parsed_pe *pe = nullptr;

ThreadCtx::ThreadCtx()
{
    thread_id = tid_counter++;
    stack = malloc(stack_size);
    stack_end = (void *)((char *)stack + stack_size);
    teb = malloc(0x2000);
    logf("Thread %u: Allocated %u bytes of stack.\n", thread_id, stack_size);
}

ThreadCtx::~ThreadCtx()
{
    if (stack != nullptr)
    {
        logf("Thread %u: Freed thread's stack.\n", thread_id, stack_size);
        free(stack);
        stack = nullptr;
        stack_end = nullptr;
    }

    if (teb != nullptr)
    {
        free(teb);
        teb = nullptr;
    }
}

void ThreadCtx::save_regs(uc_engine *uc)
{
    uc_assert(uc_reg_read(uc, UC_X86_REG_EAX, &eax));
    uc_assert(uc_reg_read(uc, UC_X86_REG_EBX, &ebx));
    uc_assert(uc_reg_read(uc, UC_X86_REG_ECX, &ecx));
    uc_assert(uc_reg_read(uc, UC_X86_REG_EDX, &edx));
    uc_assert(uc_reg_read(uc, UC_X86_REG_ESI, &esi));
    uc_assert(uc_reg_read(uc, UC_X86_REG_EDI, &edi));
    uc_assert(uc_reg_read(uc, UC_X86_REG_EIP, &eip));
    uc_assert(uc_reg_read(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_read(uc, UC_X86_REG_EBP, &ebp));
    uc_assert(uc_reg_read(uc, UC_X86_REG_EFLAGS, &eflags));
}

void ThreadCtx::restore_regs(uc_engine *uc)
{
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &eax));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EBX, &ebx));
    uc_assert(uc_reg_write(uc, UC_X86_REG_ECX, &ecx));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EDX, &edx));
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESI, &esi));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EDI, &edi));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &eip));
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EBP, &ebp));
    // uc_assert(uc_reg_write(uc, UC_X86_REG_EFLAGS, &eflags));
}

void ThreadCtx::print_stack(uc_engine *uc)
{
    logf("Thread %u stack dump:\n", thread_id);
    uint32_t sp;
    uc_assert(uc_reg_read(uc, UC_X86_REG_ESP, &sp));
    uint32_t *stk = (uint32_t *)stack;
    sp -= 20;
    uint32_t start = (sp - stack_base) / 4;
    uint32_t len = (stack_base + stack_size - sp) / 4;

    for (int i = 0; i < len; i++)
    {
        logf("%#010x: %#010x\n", stack_base + (start + i) * 4, stk[start + i]);
    }
}

void ThreadCtx::print_regs()
{
    logf("Thread %u register dump:\n", thread_id);
    logf("eax=%#010x ebx=%#010x ecx=%#010x edx=%#010x esi=%#010x edi=%#010x\n", eax, ebx, ecx, edx, esi, edi);
    logf("eip=%#010x esp=%#010x ebp=%#010x eflags=%#010x \n", eip, esp, ebp, eflags);
}

static constexpr const char *reloc_name(const peparse::reloc_type reloc_type)
{
    switch (reloc_type)
    {
    case peparse::RELOC_ABSOLUTE:
        return "ABSOLUTE";
    case peparse::RELOC_HIGH:
        return "HIGH";
    case peparse::RELOC_LOW:
        return "LOW";
    case peparse::RELOC_HIGHLOW:
        return "HIGHLOW";
    case peparse::RELOC_HIGHADJ:
        return "HIGHADJ";
    case peparse::RELOC_MIPS_JMPADDR:
        return "MIPS_JMPADDR";
    case peparse::RELOC_MIPS_JMPADDR16:
        return "MIPS_JMPADD16";
    case peparse::RELOC_DIR64:
        return "DIR64";
    default:
        return "UNKNOWN";
    }
}

void uc_assert(uc_err err, const std::string &msg)
{
    if (err != UC_ERR_OK)
    {
        std::string m(msg);
        m += ": ";
        m += uc_strerror(err);
        m += " (" + std::to_string(err) + ")";

        throw std::runtime_error(m);
    }
}

uint32_t push_jitregion(uc_engine *uc, const uint8_t *code, size_t code_size)
{
    uc_err err;

    if ((jit_last + code_size) > (jit_base + jit_size))
    {
        logf("Resizing JIT region [%#010x-%#010x] -> [%#010x-%#010x]...\n", jit_base, jit_base + jit_size, jit_base, jit_base + jit_size + 0x1000);

        uint32_t start = jit_base + jit_size;
        err = uc_mem_map(uc, start, 0x1000, UC_PROT_EXEC | UC_PROT_READ);
        if (err != UC_ERR_OK)
        {
            std::string msg = "Failed to map syscall thunk section: ";
            msg += uc_strerror(err);
            msg += " (" + std::to_string(err) + ")";

            throw std::runtime_error(msg);
        }

        jit_size += 0x1000;
    }

    err = uc_mem_write(uc, jit_last, code, code_size);
    if (err != UC_ERR_OK)
    {
        std::string msg = "Failed to write thunk code: ";
        msg += uc_strerror(err);
        msg += " (" + std::to_string(err) + ")";

        throw std::runtime_error(msg);
    }

    uint32_t code_addr = jit_last;
    jit_last += code_size;

    return code_addr;
}

uint32_t add_syscall(uc_engine *uc, uint32_t id, void (*cb)(uc_engine *, uint32_t))
{
    uint8_t thunk[8];
    uc_err err;
    uint32_t thunk_addr = 0;

    memset(thunk, 0xcc, sizeof(thunk));
    thunk[0] = 0x68; // push id
    *((uint32_t *)&thunk[1]) = id;
    thunk[5] = 0xcd; // int 0x55
    thunk[6] = 0x55;

    thunk_cbs.push_back(cb);

    return push_jitregion(uc, thunk, sizeof(thunk));
}

peparse::parsed_pe *load_pe(uc_engine *uc, const char *name)
{
    logf("Loading file: %s\n", name);

    peparse::parsed_pe *pe = peparse::ParsePEFromFile(name);
    if (!pe)
    {
        throw std::runtime_error("Failed to load a PE file.");
    }

    auto &nt = pe->peHeader.nt;
    if (nt.FileHeader.Machine != peparse::IMAGE_FILE_MACHINE_I386)
    {
        throw std::runtime_error("Not an x86 executable.");
    }

    uint32_t image_header_size = pe->peHeader.dos.e_lfanew + (offsetof(peparse::nt_header_32, OptionalHeader) + nt.FileHeader.SizeOfOptionalHeader + (nt.FileHeader.NumberOfSections * sizeof(peparse::image_section_header)));
    uint32_t image_base = nt.OptionalHeader.ImageBase;
    uc_mem_unmap(uc, image_base, align_address(image_header_size));
    uc_assert(uc_mem_map(uc, image_base, align_address(image_header_size), UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC), "Failed to map image header section");
    uc_assert(uc_mem_write(uc, image_base, pe->fileBuffer->buf, image_header_size), "Failed to write image header section");

    peparse::IterSec(
        pe, [](void *p, const peparse::VA &sect_base, const std::string &sect_name, const peparse::image_section_header &sect_hdr, const peparse::bounded_buffer *sect_data) -> int
        {
            auto uc = (uc_engine *)p;
            auto addr = sect_data->buf;
            char protflags[4] = "---";
            uint32_t perms = 0;

            if ((sect_hdr.Characteristics & peparse::IMAGE_SCN_MEM_READ) != 0)
            {
                protflags[0] = 'r';
                perms |= UC_PROT_READ;
            }

            if ((sect_hdr.Characteristics & peparse::IMAGE_SCN_MEM_WRITE) != 0)
            {
                protflags[1] = 'w';
                perms |= UC_PROT_WRITE;
            }

            if ((sect_hdr.Characteristics & peparse::IMAGE_SCN_MEM_EXECUTE) != 0)
            {
                protflags[2] = 'x';
                perms |= UC_PROT_EXEC;
            }

            uint32_t size_aligned = align_address(sect_hdr.Misc.VirtualSize);

            if (!sect_data)
            {
                logf("Allocating empty region: %#010lx-%#010lx %-12s [%s] [flags=%08x, host_addr=%p]\n", sect_base, sect_base + size_aligned, sect_name.c_str(), protflags, sect_hdr.Characteristics, addr);

                uc_mem_unmap(uc, sect_base, size_aligned);
                uc_assert(uc_mem_map(uc, sect_base, size_aligned, perms), "Failed to map section");
            }
            else
            {
                logf("Mapping: %#010lx-%#010lx %-12s [%s] [flags=%08x, host_addr=%p]\n", sect_base, sect_base + size_aligned, sect_name.c_str(), protflags, sect_hdr.Characteristics, addr);

                uc_mem_unmap(uc, sect_base, size_aligned);
                uc_assert(uc_mem_map(uc, sect_base, size_aligned, perms), "Failed to map section");
                uc_assert(uc_mem_write(uc, sect_base, sect_data->buf, sect_data->bufLen), "Failed to write section");
            }

            return 0;
        },
        uc);

    peparse::IterExpVA(
        pe, [](void *p, const peparse::VA &export_addr, const std::string &mod_name, const std::string &sym_name) -> int
        {
            auto cached = import_cache.find(sym_name);
            if (cached == import_cache.end())
            {
                logf("Export: %s!%s -> %#010lx\n", mod_name.c_str(), sym_name.c_str(), export_addr);
                import_cache[sym_name] = (uint32_t)export_addr;

                if (exports.find(sym_name) == exports.end())
                {
                    Export ex = {sym_name, nullptr, nullptr, 0, export_addr};
                    exports[sym_name] = ex;
                    exports["_" + sym_name] = ex;
                }
            }

            return 0;
        },
        uc);

    printf("Resolving imports:\n");
    peparse::IterImpVAString(
        pe, [](void *p, const peparse::VA &import_addr, const std::string &mod_name, const std::string &sym_name) -> int
        {
            auto uc = (uc_engine *)p;
            char buff[512] = "";

            logf("Import: %p - %s %s\n", import_addr, mod_name.c_str(), sym_name.c_str());
            auto ex = exports.find(sym_name);
            if (ex != exports.end())
            {
                uint32_t addr = 0xdeaddeef;
                auto cached = import_cache.find(sym_name);
                if (cached != import_cache.end())
                {
                    addr = cached->second;
                }
                else if (ex->second.raw_address != 0)
                {
                    addr = ex->second.raw_address;
                    import_cache[sym_name] = addr;
                }
                else if (ex->second.raw_code != nullptr)
                {
                    addr = push_jitregion(uc, ex->second.raw_code, ex->second.raw_code_size);
                    import_cache[sym_name] = addr;
                }
                else if (ex->second.cb != nullptr)
                {
                    addr = add_syscall(uc, thunk_cbs.size(), ex->second.cb);
                    import_cache[sym_name] = addr;
                }

                uc_err err = uc_mem_write(uc, import_addr, &addr, 4);
                if (err != UC_ERR_OK)
                {
                    std::string msg = "Failed to link IAT entry: ";
                    msg += uc_strerror(err);
                    msg += " (" + std::to_string(err) + ")";

                    throw std::runtime_error(msg);
                }

                sprintf(buff, "%s: %#010x -> %#010x\n", sym_name.c_str(), import_addr, addr);
                export_log += buff;
            }

            return 0;
        },
        uc);

    return pe;
}

static bool hook_segfault(uc_engine *uc, uc_mem_type type,
                          uint64_t address, int size, int64_t value, void *user_data)
{
    auto thread = (ThreadCtx *)user_data;
    thread->save_regs(uc);

    logf("Access Violation at %#010x [addr=%#010lx, size=%#010x, value=%#010lx]\n", thread->eip, address, size, value);
    thread->print_stack(uc);
    //thread->print_regs();

    uc_emu_stop(uc);
    emu_failed = true;

    return false;
}

static bool hook_interrupt(uc_engine *uc, uint32_t int_num, void *user_data)
{
    // TODO implement support and call SEH handlers

    switch (int_num)
    {
    case 0: // division by zero
        logf("Division by zero\n");
        return false;
    case 1: // debug
        return true;
    case 3: // breakpoint
        logf("Breakpoint hit\n");
        return true;
    case 6: // invalid cpu opcode
        logf("Invalid CPU opcode\n");
        return false;
    case 0x0d: // GPF
        logf("General protection fault\n");
        return false;
    case 0x0e: // page fault
        logf("Page fault\n");
        return false;
    case 0x10: // fp exception
        logf("Floating point exception\n");
        return false;
    case 0x55:
    { // emulator function call
        uint32_t esp;
        uint32_t call_id;

        uc_assert(uc_reg_read(uc, UC_X86_REG_ESP, &esp));
        uc_assert(uc_mem_read(uc, esp, &call_id, 4));
        esp += 4;

        if (call_id < thunk_cbs.size())
        {
            thunk_cbs[call_id](uc, esp);
        }

        //logf("call id: %#010x\n", call_id);

        return true;
    }
    }

    logf("Unhandled interrupt: %#02x\n", int_num);

    uc_emu_stop(uc);
    emu_failed = true;

    return false;
}

static bool hook_trace(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    auto thread = (ThreadCtx *)user_data;
    thread->save_regs(uc);
    thread->print_regs();

    return true;
}

static uc_engine *uc = nullptr;

void emu_loop()
{
    if (emu_failed)
        return;

    uc_assert(uc_reg_read(uc, UC_X86_REG_EIP, &curr_thread_ref->eip));
    uc_err err = uc_emu_start(uc, curr_thread_ref->eip, 0, 10000, 100000);
    if (err != UC_ERR_OK)
    {
        logf("Emulation error: %s (%u)\n", uc_strerror(err), err);
        logf("Export log:\n%s\n", export_log.c_str());

        curr_thread_ref->save_regs(uc);
        curr_thread_ref->print_regs();
        emu_failed = true;
    }
}

int emu_init()
{
    uc_err err;

    logf("Initializing CPU emulator...\n");
    err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    if (err != UC_ERR_OK)
    {
        logf("Failed to initialize CPU emulator: uc_open() with error returned: %s (%u)\n",
             uc_strerror(err), err);
        return -1;
    }

    if (align_address(heap_size) != heap_size)
    {
        logf("Heap size must be page-aligned (4096 bytes)!\n");
        return -1;
    }

    heap = malloc(heap_size);
    if (heap == nullptr)
    {
        logf("Failed to allocate heap memory!\n");
        return -1;
    }

    logf("Allocated %d bytes of heap memory.\n", heap_size);
    err = uc_mem_map_ptr(uc, heap_base, heap_size, UC_PROT_READ | UC_PROT_WRITE, heap);
    if (err != UC_ERR_OK)
    {
        logf("Failed to map heap memory: %s (%d)\n", uc_strerror(err), err);
        return -1;
    }

    try
    {
        install_exports(uc);
        auto dll_pe = load_pe(uc, "msvcrt.dll");
        pe = load_pe(uc, "KeroBlaster.exe");

        uc_hook segfault;
        uc_hook interrupt;
        uc_hook trace;
        SegmentDescriptor gdt[32];
        uc_x86_mmr gdtr;
        memset(&gdt, 0, sizeof(gdt));
        memset(&gdtr, 0, sizeof(gdtr));

        emu_spinlock_thunk = push_jitregion(uc, emu_spinlock_code, sizeof(emu_spinlock_code));

        logf("Main thread setup\n");
        auto main_thread = new ThreadCtx();
        threads.push_back(main_thread);
        curr_thread = main_thread->thread_id;
        curr_thread_ref = main_thread;

        uint32_t dll_entry = dll_pe->peHeader.nt.OptionalHeader.ImageBase + dll_pe->peHeader.nt.OptionalHeader.AddressOfEntryPoint;
        uint32_t program_entry = pe->peHeader.nt.OptionalHeader.ImageBase + pe->peHeader.nt.OptionalHeader.AddressOfEntryPoint;
        uint32_t param;
        main_thread->eip = dll_entry;
        main_thread->esp = stack_base + stack_size - 0x20;
        main_thread->ebp = 0;
        main_thread->restore_regs(uc);

        curr_module_handle = pe->peHeader.nt.OptionalHeader.ImageBase; // TIL

        uc_assert(uc_mem_map_ptr(uc, stack_base, stack_size, UC_PROT_READ | UC_PROT_WRITE, main_thread->stack), "Failed to map stack");
        uc_assert(uc_mem_map_ptr(uc, seg_base, 0x2000, UC_PROT_READ | UC_PROT_WRITE, main_thread->teb), "Failed to map TEB");

        // write program entry point
        uc_assert(uc_mem_write(uc, main_thread->esp, &program_entry, 4));
        // write DllEntryPoint params
        uc_assert(uc_mem_write(uc, main_thread->esp + 4, &curr_module_handle, 4)); // hInst
        param = 1;
        uc_assert(uc_mem_write(uc, main_thread->esp + 8, &param, 4));  // dwReason = DLL_PROCESS_ATTACH
        uc_assert(uc_mem_write(uc, main_thread->esp + 12, &param, 4)); // lpReserved, must be non-zero otherwise msvcrt will call some termination procedure

        logf("TEB setup\n");
        auto teb = (TIB32 *)main_thread->teb;
        teb->stack_base = stack_base;
        teb->stack_top = stack_base + stack_size;
        teb->teb_linear = seg_base;

        logf("GDT setup\n");
        int cs = 0x73;
        int ss = 0x88;
        int ds = 0x7b;
        int es = 0x7b;
        int fs = 0x83;

        gdtr.base = gdt_base;
        gdtr.limit = 31 * sizeof(SegmentDescriptor) - 1;

        init_descriptor(&gdt[14], 0, 0xfffff000, 1);   // CS
        init_descriptor(&gdt[15], 0, 0xfffff000, 0);   // DS
        init_descriptor(&gdt[16], seg_base, 0xfff, 0); // FS - TIB
        init_descriptor(&gdt[17], 0, 0xfffff000, 0);   // SS
        gdt[17].dpl = 0;

        uc_assert(uc_mem_map(uc, gdt_base, 0x10000, UC_PROT_READ | UC_PROT_WRITE), "Failed to map GDT");
        uc_assert(uc_mem_write(uc, gdt_base, &gdt, sizeof(gdt)), "Failed to write GDT");

        uc_assert(uc_reg_write(uc, UC_X86_REG_GDTR, &gdtr));
        uc_assert(uc_reg_write(uc, UC_X86_REG_CS, &cs));
        uc_assert(uc_reg_write(uc, UC_X86_REG_DS, &ds));
        uc_assert(uc_reg_write(uc, UC_X86_REG_ES, &es));
        uc_assert(uc_reg_write(uc, UC_X86_REG_FS, &fs));
        uc_assert(uc_reg_write(uc, UC_X86_REG_SS, &ss));

        uc_mem_region *regions;
        uint32_t count;
        uc_mem_regions(uc, &regions, &count);

        logf("Memory map:\n");
        for (int i = 0; i < count; i++)
        {
            char perm[4] = "---";
            auto &region = regions[i];
            if (region.perms & UC_PROT_READ)
                perm[0] = 'r';
            if (region.perms & UC_PROT_WRITE)
                perm[1] = 'w';
            if (region.perms & UC_PROT_EXEC)
                perm[2] = 'x';
            logf("%#010lx-%#010lx [%s]\n", region.begin, region.end, perm);
        }

        logf("Exception / interrupt handler setup\n");

        uc_assert(uc_hook_add(uc, &segfault, UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED, (void *)hook_segfault, main_thread, 1, 0), "Failed to register segfault hook");
        uc_assert(uc_hook_add(uc, &interrupt, UC_HOOK_INTR, (void *)hook_interrupt, main_thread, 1, 0), "Failed to register interrupt hook");
        uc_assert(uc_hook_add(uc, &trace, UC_HOOK_CODE, (void *)hook_trace, main_thread, image_base, 0x80000000), "Failed to register trace hook");
    }
    catch (std::exception &e)
    {
        printf("An error occured during initialization: %s\n", e.what());
        return -1;
    }

    return 0;
}