#include <unicorn/unicorn.h>
#include <unordered_map>
#include "common.h"
#include "exports.h"

std::unordered_map<std::string, Export> exports;

extern void install_kernel32_exports(uc_engine* uc);
extern void install_user32_exports(uc_engine* uc);
extern void install_comctl32_exports(uc_engine* uc);
//extern void install_msvcrt_exports(uc_engine* uc);
extern void install_winmm_exports(uc_engine* uc);

void install_exports(uc_engine* uc) {
    install_kernel32_exports(uc);
    install_user32_exports(uc);
    install_comctl32_exports(uc);
    //install_msvcrt_exports(uc);
    install_winmm_exports(uc);
}