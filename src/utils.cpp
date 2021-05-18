#include <string>
#include <unicorn/unicorn.h>
#include "common.h"

std::u16string read_u16string(uc_engine* uc, uint32_t address) {
    std::u16string s;
    char16_t chr;

    do {
        uc_assert(uc_mem_read(uc, address, &chr, 2));
        s += chr;
    } while (chr != 0);

    return s;
}