cmake_minimum_required(VERSION 3.10.0)
project(keroloader2 VERSION 0.1.0)

option(BUILD_SHARED_LIBS "" OFF)
option(UNICORN_INSTALL "" OFF)
option(UNICORN_BUILD_SAMPLES "" OFF)
set(UNICORN_ARCH "x86")
#set (CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fno-omit-frame-pointer -fsanitize=address")
#set (CMAKE_LINKER_FLAGS_DEBUG "${CMAKE_LINKER_FLAGS_DEBUG} -fno-omit-frame-pointer -fsanitize=address")

add_subdirectory(unicorn)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED true)
add_executable(keroloader2 
    src/main.cpp
    src/emulator.cpp
    src/utils.cpp
    src/gstw_table.cpp
    src/exports.cpp
    src/exports_comctl32.cpp
    src/exports_kernel32.cpp
    src/exports_user32.cpp
    src/exports_winmm.cpp
    src/exports_shlwapi.cpp
    src/pe-parse/buffer.cpp
    src/pe-parse/parse.cpp
    src/pe-parse/unicode_codecvt.cpp
    src/sokol/sokol_impl.cpp
    src/sokol/imgui.cpp
    src/sokol/imgui_tables.cpp
    src/sokol/imgui_widgets.cpp
    src/sokol/imgui_draw.cpp
    src/tinyalloc/tinyalloc.cpp
)

target_include_directories(keroloader2 PRIVATE 
    "${CMAKE_CURRENT_SOURCE_DIR}/unicorn/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/unicorn/qemu"
    "${CMAKE_CURRENT_SOURCE_DIR}/unicorn/qemu/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/unicorn/qemu/tcg")

target_link_directories(keroloader2 PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/unicorn")

target_link_libraries(keroloader2 unicorn pthread GL X11 Xi Xcursor dl)
#target_link_libraries(keroloader2 libunicorn.a)