#pragma once

#include <unordered_map>
#include <string>
#include <unicorn/unicorn.h>

struct Export
{
    std::string name;
    void (*cb)(uc_engine *uc, uint32_t esp);
    uint8_t* raw_code = nullptr;
    uint32_t raw_code_size = 0;
    uint32_t raw_address = 0;
};

extern std::unordered_map<std::string, Export> exports;

void install_exports(uc_engine* uc);