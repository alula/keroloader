#include <cstdlib>

#include "sokol/imconfig.h"
#include "sokol/imgui.h"

#include "sokol/sokol_app.h"
#include "sokol/sokol_gfx.h"
#include "sokol/sokol_time.h"
#include "sokol/sokol_glue.h"
#include "sokol/sokol_imgui.h"

static uint64_t last_time = 0;
static bool show_test_window = true;
static bool show_another_window = false;

static sg_pass_action pass_action;

extern void emu_loop();
extern int emu_init();
extern void logf(const char *fmt, ...);

char msgbox_title_txt[2048] = {0};
char msgbox_message_txt[4096] = {0};

void init(void)
{
    sg_desc desc = {};
    simgui_desc_t simgui_desc = {};

    desc.context = sapp_sgcontext();
    sg_setup(&desc);
    stm_setup();

    simgui_setup(&simgui_desc);

    pass_action.colors[0].action = SG_ACTION_CLEAR;
    pass_action.colors[0].value = {0.0f, 0.0f, 0.0f, 1.0f};

    ImGui::GetIO().IniFilename = nullptr;

    int code = emu_init();
    if (code != 0)
    {
        exit(code);
    }
}

void frame(void)
{
    const int width = sapp_width();
    const int height = sapp_height();
    const double delta_time = stm_sec(stm_laptime(&last_time));

    //logf("emu loop %s %s\n", msgbox_message_txt, msgbox_title_txt);
    emu_loop();

    simgui_new_frame(width, height, delta_time);

    if (msgbox_message_txt[0])
    {
        if (msgbox_title_txt[0] == 0)
        {
            strcpy(msgbox_title_txt, "Message");
        }

        auto io = ImGui::GetIO();
        ImGui::SetNextWindowSizeConstraints(ImVec2(250.0f, 80.0f), ImVec2(400.0f, 200.0f));
        ImGui::SetNextWindowPos(ImVec2(io.DisplaySize.x / 2.f, io.DisplaySize.y / 2.f), ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
        ImGui::Begin(msgbox_title_txt, nullptr, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoCollapse);
        ImGui::TextWrapped("%s", msgbox_message_txt);

        if (ImGui::Button("OK"))
        {
        }

        ImGui::End();
    }

    sg_begin_default_pass(&pass_action, width, height);
    simgui_render();
    sg_end_pass();
    sg_commit();
}

void cleanup(void)
{
    simgui_shutdown();
    sg_shutdown();
}

void input(const sapp_event *event)
{
    simgui_handle_event(event);
}

sapp_desc sokol_main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;
    sapp_desc desc = {};
    desc.init_cb = init;
    desc.frame_cb = frame;
    desc.cleanup_cb = cleanup;
    desc.event_cb = input;
    desc.width = 800;
    desc.height = 480;
    desc.gl_force_gles2 = true;
    desc.window_title = "KeroLoader";
    desc.ios_keyboard_resizes_canvas = false;
    desc.icon.sokol_default = true;
    return desc;
}