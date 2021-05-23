#include <cstdlib>
#include <clocale>
#include <locale>

#include "sokol_pipeline.h"

static uint64_t last_time = 0;
static bool show_test_window = true;
static bool show_another_window = false;

static sg_pass_action pass_action;
sokol_state state;

extern void emu_loop();
extern int emu_init();
extern void logf(const char *fmt, ...);

int window_width = 0;
int window_height = 0;
char msgbox_title_txt[2048] = {0};
char msgbox_message_txt[4096] = {0};

void init(void)
{
    sg_desc desc = {};
    sgl_desc_t sgl_desc = {};
    simgui_desc_t simgui_desc = {};

    desc.context = sapp_sgcontext();
    sg_setup(&desc);
    sgl_setup(&sgl_desc);
    stm_setup();

    simgui_setup(&simgui_desc);

    pass_action.colors[0].action = SG_ACTION_CLEAR;
    pass_action.colors[0].value = {0.0f, 0.0f, 0.0f, 1.0f};

    state.deflt.pass_action = pass_action;
    sg_pipeline_desc pdesc = {
        .depth = {
            .compare = SG_COMPAREFUNC_LESS_EQUAL,
            .write_enabled = true,
        },
        .cull_mode = SG_CULLMODE_BACK,
    };
    state.deflt.pip = sgl_make_pipeline(&pdesc);

    ImGui::GetIO().IniFilename = nullptr;

    int code = emu_init();
    if (code != 0)
    {
        exit(code);
    }
}

extern void test_draw();

void frame(void)
{
    const int width = sapp_width();
    const int height = sapp_height();
    const double delta_time = stm_sec(stm_laptime(&last_time));

    simgui_new_frame(width, height, delta_time);
    sg_begin_default_pass(&pass_action, width, height);

    //logf("emu loop %s %s\n", msgbox_message_txt, msgbox_title_txt);
    sgl_defaults();
    sgl_load_pipeline(state.deflt.pip);
    emu_loop();
    sgl_draw();

    if (msgbox_message_txt[0])
    {
        if (msgbox_title_txt[0] == 0)
        {
            strcpy(msgbox_title_txt, "Message");
        }

        auto io = ImGui::GetIO();
        ImGui::SetNextWindowSizeConstraints(ImVec2(250.0f, 80.0f), ImVec2(700.0f, 200.0f));
        ImGui::SetNextWindowPos(ImVec2(io.DisplaySize.x / 2.f, io.DisplaySize.y / 2.f), ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
        ImGui::Begin(msgbox_title_txt, nullptr, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoCollapse);
        ImGui::TextWrapped("%s", msgbox_message_txt);

        if (ImGui::Button("OK"))
        {
        }

        ImGui::End();
    }

    test_draw();
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

    setlocale(LC_ALL, "C");
    std::locale::global(std::locale("C"));

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
    desc.icon.sokol_default = false;
    return desc;
}