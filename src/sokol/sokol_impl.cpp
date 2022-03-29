#define SOKOL_IMPL
#ifdef __ANDROID__
#define SOKOL_GLES3
#else
#define SOKOL_GLCORE33
#endif

#include "sokol_app.h"
#include "sokol_gfx.h"
#include "sokol_time.h"
#include "sokol_glue.h"
#include "imconfig.h"
#include "imgui.h"
#include "sokol_imgui.h"
#include "sokol_gl.h"
#include "sokol_audio.h"