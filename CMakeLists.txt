cmake_minimum_required(VERSION 3.10.0)
project(keroloader2 VERSION 0.1.0)

option(BUILD_SHARED_LIBS "" OFF)
option(UNICORN_INSTALL "" OFF)
option(UNICORN_BUILD_SAMPLES "" OFF)
set(UNICORN_ARCH "x86")
#set (CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fno-omit-frame-pointer -fsanitize=address")
#set (CMAKE_LINKER_FLAGS_DEBUG "${CMAKE_LINKER_FLAGS_DEBUG} -fno-omit-frame-pointer -fsanitize=address")

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3 -flto")
# set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -fprofile-generate=profiling")
# set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -fprofile-use=profiling")

if (NOT ANDROID)
    add_subdirectory(unicorn)
endif ()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED true)
set(KL_SOURCES
        src/main.cpp
        src/emulator.cpp
        src/utils.cpp
        src/gstw_table.cpp
        src/exports.cpp
        src/exports_comctl32.cpp
        src/exports_d3d9.cpp
        src/exports_dsound.cpp
        src/exports_kernel32.cpp
        src/exports_user32.cpp
        src/exports_msvcrt.cpp
        src/exports_winmm.cpp
        src/exports_steam_api.cpp
        src/exports_shlwapi.cpp
        src/pe-parse/buffer.cpp
        src/pe-parse/parse.cpp
        src/pe-parse/unicode_codecvt.cpp
        src/sokol/sokol_impl.cpp
        src/sokol/imgui.cpp
        src/sokol/imgui_tables.cpp
        src/sokol/imgui_widgets.cpp
        src/sokol/imgui_draw.cpp
        src/tinyalloc/tinyalloc.cpp)

if (ANDROID)
    add_library(keroloader2 SHARED ${KL_SOURCES})
else ()
    add_executable(keroloader2 ${KL_SOURCES})
endif ()

target_include_directories(keroloader2 PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/unicorn/include"
        "${CMAKE_CURRENT_SOURCE_DIR}/unicorn/qemu"
        "${CMAKE_CURRENT_SOURCE_DIR}/unicorn/qemu/include"
        "${CMAKE_CURRENT_SOURCE_DIR}/unicorn/qemu/tcg")

target_link_directories(keroloader2 PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/unicorn")

if (ANDROID)
    target_link_libraries(keroloader2 "${CMAKE_CURRENT_SOURCE_DIR}/prebuilts/android/${ANDROID_ABI}/libunicorn.a" dl GLESv3 EGL OpenSLES android log)
elseif (UNIX)
    target_link_libraries(keroloader2 unicorn pthread GL X11 Xi Xcursor dl asound)
endif ()

#target_link_libraries(keroloader2 libunicorn.a)