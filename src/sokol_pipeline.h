#pragma once

#include "sokol/imconfig.h"
#include "sokol/imgui.h"

#include "sokol/sokol_app.h"
#include "sokol/sokol_gfx.h"
#include "sokol/sokol_time.h"
#include "sokol/sokol_glue.h"
#include "sokol/sokol_imgui.h"
#include "sokol/sokol_gl.h"
#include "sokol/sokol_audio.h"

struct sokol_state {
    struct {
        sg_pass_action pass_action;
        sg_pass pass;
        sg_pipeline pip;
        sg_bindings bind;
    } offscreen;
    struct {
        sg_pass_action pass_action;
        sgl_pipeline pip;
        sg_bindings bind;
    } deflt;
};

extern sokol_state state;