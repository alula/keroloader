#include <cstdlib>
#include <clocale>
#include <locale>
#include <filesystem>
#include <unistd.h>
#if defined(__ANDROID__)
#include <android/native_activity.h>
#endif

#include "sokol_pipeline.h"

static uint64_t last_time = 0;
static bool show_test_window = true;
static bool show_another_window = false;

static sg_pass_action pass_action;
sokol_state state;

extern void emu_loop();
extern int emu_init();
extern void logf(const char *fmt, ...);
extern void dsound_stream_cb(float *buffer, int num_frames, int num_channels);

int window_width = 0;
int window_height = 0;
char msgbox_title_txt[2048] = {0};
char msgbox_message_txt[4096] = {0};

void init(void)
{
    sg_desc desc = {};
    sgl_desc_t sgl_desc = {};
    simgui_desc_t simgui_desc = {};
    saudio_desc saudio_desc = {};

    desc.context = sapp_sgcontext();
    saudio_desc.sample_rate = 44100;
    saudio_desc.num_channels = 2;
    saudio_desc.stream_cb = dsound_stream_cb;
    
    sg_setup(&desc);
    sgl_setup(&sgl_desc);
    stm_setup();
    saudio_setup(&saudio_desc);
    simgui_setup(&simgui_desc);

    pass_action.colors[0].action = SG_ACTION_CLEAR;
    pass_action.colors[0].value = {0.0f, 0.0f, 0.0f, 1.0f};

    state.deflt.pass_action = pass_action;
    sg_pipeline_desc pdesc = {
        .depth = {
            //.compare = SG_COMPAREFUNC_LESS_EQUAL,
            .write_enabled = false,
        },
        .cull_mode = SG_CULLMODE_NONE,
    };
    pdesc.colors[0].blend = (sg_blend_state){
        .enabled = true,
        .src_factor_rgb = SG_BLENDFACTOR_SRC_ALPHA,
        .dst_factor_rgb = SG_BLENDFACTOR_ONE_MINUS_SRC_ALPHA};
    state.deflt.pip = sgl_make_pipeline(&pdesc);
    ImGui::GetIO().IniFilename = nullptr;
    auto style = ImGui::GetStyle();
    style.FramePadding = ImVec2(4.0, 4.0);

#if defined(__ANDROID__)
    auto activity = reinterpret_cast<const ANativeActivity *>(sapp_android_get_native_activity());
    chdir(activity->internalDataPath);
    logf("path: %s\n", activity->internalDataPath);
#endif

    strcpy(msgbox_title_txt, "KeroLoader2 initialization error");

    int code = emu_init();
    if (code != 0)
    {
        exit(code);
    }
}

extern void graphics_cleanup();
extern uint32_t get_ticks();

extern uint32_t emu_sleep;
extern bool emu_nointerrupt;
extern float render_x_offset;
float memex = 0, memey = 0;

void frame(void)
{
    const int width = sapp_width();
    const int height = sapp_height();
    const double delta_time = stm_sec(stm_laptime(&last_time));
    render_x_offset = ((sapp_widthf() / sapp_heightf() * 320.0f) - 570.0f) / 2.0f;

    if (emu_sleep != 0)
    {
        if (get_ticks() >= emu_sleep)
            emu_sleep = 0;
    }

    simgui_new_frame(width, height, delta_time);
    sg_begin_default_pass(&pass_action, width, height);

    sgl_defaults();
    sgl_load_pipeline(state.deflt.pip);

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
    else
    {
        emu_loop();
        emu_nointerrupt = true;
    }

    // sgl_disable_texture();
    // sgl_begin_quads();
    // sgl_c1i(0xff0000ff);
    // sgl_v2f(memex - 3.0f, memey - 3.0f);
    // sgl_v2f(memex + 3.0f, memey - 3.0f);
    // sgl_v2f(memex + 3.0f, memey + 3.0f);
    // sgl_v2f(memex - 3.0f, memey + 3.0f);
    // sgl_end();

    sgl_draw();
    simgui_render();
    sg_end_pass();
    sg_commit();

    graphics_cleanup();
}

void cleanup(void)
{
    simgui_shutdown();
    sgl_shutdown();
    sg_shutdown();
    saudio_shutdown();
}

static int to_vk(sapp_keycode code)
{
    // todo: add all windows virtual keycodes
    switch (code)
    {
    case SAPP_KEYCODE_ESCAPE:
        return 0x1b;
    case SAPP_KEYCODE_LEFT:
        return 0x25;
    case SAPP_KEYCODE_UP:
        return 0x26;
    case SAPP_KEYCODE_RIGHT:
        return 0x27;
    case SAPP_KEYCODE_DOWN:
        return 0x28;
    case SAPP_KEYCODE_A:
        return 0x41;
    case SAPP_KEYCODE_S:
        return 0x53;
    case SAPP_KEYCODE_X:
        return 0x58;
    case SAPP_KEYCODE_Z:
        return 0x5a;
    default:
        return 0;
    }
}

extern void push_window_message(uint32_t msg, uint32_t lparam, uint32_t rparam);
extern void push_touch(int type, float x, float y);

void input(const sapp_event *event)
{
    if (simgui_handle_event(event))
        return;

    if (event->type == SAPP_EVENTTYPE_KEY_DOWN)
    {
        int key = to_vk(event->key_code);
        if (key != 0)
            push_window_message(0x100, key, 0);
    }
    else if (event->type == SAPP_EVENTTYPE_KEY_UP)
    {
        int key = to_vk(event->key_code);
        if (key != 0)
            push_window_message(0x101, key, 0);
    }
    else if (event->type == SAPP_EVENTTYPE_TOUCHES_BEGAN)
    {
        for (int i = 0; i < event->num_touches; i++)
        {
            if (event->touches[i].changed)
            {
                float touch_x = event->touches[i].pos_x / sapp_heightf() * 320.0f - render_x_offset;
                float touch_y = event->touches[i].pos_y / sapp_heightf() * 320.0f;
                // memex = touch_x; memey = touch_y;
                push_touch(0, touch_x, touch_y);
            }
        }
    }
    else if (event->type == SAPP_EVENTTYPE_TOUCHES_MOVED)
    {
        for (int i = 0; i < event->num_touches; i++)
        {
            if (event->touches[i].changed)
            {
                float touch_x = event->touches[i].pos_x / sapp_heightf() * 320.0f - render_x_offset;
                float touch_y = event->touches[i].pos_y / sapp_heightf() * 320.0f;
                // memex = touch_x; memey = touch_y;
                push_touch(1, touch_x, touch_y);
            }
        }
    }
    else if (event->type == SAPP_EVENTTYPE_TOUCHES_CANCELLED || event->type == SAPP_EVENTTYPE_TOUCHES_ENDED)
    {
        for (int i = 0; i < event->num_touches; i++)
        {
            if (event->touches[i].changed)
            {
                float touch_x = event->touches[i].pos_x / sapp_heightf() * 320.0f - render_x_offset;
                float touch_y = event->touches[i].pos_y / sapp_heightf() * 320.0f;
                // memex = touch_x; memey = touch_y;
                push_touch(2, touch_x, touch_y);
            }
        }
    }
    else if (event->type == SAPP_EVENTTYPE_MOUSE_DOWN)
    {
        float touch_x = event->mouse_x / sapp_heightf() * 320.0f - render_x_offset;
        float touch_y = event->mouse_y / sapp_heightf() * 320.0f;
        push_touch(0, touch_x, touch_y);
    }
    else if (event->type == SAPP_EVENTTYPE_MOUSE_MOVE)
    {
        float touch_x = event->mouse_x / sapp_heightf() * 320.0f - render_x_offset;
        float touch_y = event->mouse_y / sapp_heightf() * 320.0f;
        push_touch(1, touch_x, touch_y);
    }
    else if (event->type == SAPP_EVENTTYPE_MOUSE_UP)
    {
        float touch_x = event->mouse_x / sapp_heightf() * 320.0f - render_x_offset;
        float touch_y = event->mouse_y / sapp_heightf() * 320.0f;
        push_touch(2, touch_x, touch_y);
    }
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
    desc.width = 570;
    desc.height = 320;
    desc.high_dpi = false;
    desc.gl_force_gles2 = true;
    desc.window_title = "KeroLoader";
    desc.ios_keyboard_resizes_canvas = false;
    desc.icon.sokol_default = false;
    return desc;
}