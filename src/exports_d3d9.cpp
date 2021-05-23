#include <cstdint>
#include <ctime>
#include <cstring>
#include <string>
#include "common.h"
#include "exports.h"
#include "windows/dxerror.h"

#include "sokol_pipeline.h"

#ifndef _HRESULT_DEFINED
#define _HRESULT_DEFINED
typedef uint32_t HRESULT;
#endif

struct IDInput8W
{
    uint32_t vtbl;
};

struct IDInput8WVtable
{
    uint32_t QueryInterface = 0xdead0401;
    uint32_t AddRef = 0xdead0402;
    uint32_t Release = 0xdead0403;
    uint32_t CreateDevice = 0xdead0404;
    uint32_t EnumDevices = 0xdead0405;
    uint32_t GetDeviceStatus = 0xdead0406;
    uint32_t RunControlPanel = 0xdead0407;
    uint32_t Initialize = 0xdead0408;
    uint32_t FindDevice = 0xdead0409;
    uint32_t EnumDevicesBySemantics = 0xdead040a;
    uint32_t ConfigureDevices = 0xdead040b;

    void Init(uc_engine *uc);
};

struct ID3D9XSprite
{
    uint32_t vtbl;
};

struct ID3D9XSpriteVtable
{
    uint32_t QueryInterface = 0xdead0501;
    uint32_t AddRef = 0xdead0502;
    uint32_t Release = 0xdead0503;
    uint32_t GetDevice = 0xdead0504;
    uint32_t GetTransform = 0xdead0505;
    uint32_t SetTransform = 0xdead0506;
    uint32_t SetWorldViewRH = 0xdead0507;
    uint32_t SetWorldViewLH = 0xdead0508;
    uint32_t Begin = 0xdead0509;
    uint32_t Draw = 0xdead050a;
    uint32_t Flush = 0xdead050b;
    uint32_t End = 0xdead050c;
    uint32_t OnLostDevice = 0xdead050d;
    uint32_t OnResetDevice = 0xdead050e;

    void Init(uc_engine *uc);
};

struct ID3D9
{
    uint32_t vtbl;
};

struct ID3D9Vtable
{
    uint32_t QueryInterface = 0xdead0101;
    uint32_t AddRef = 0xdead0102;
    uint32_t Release = 0xdead0103;
    uint32_t RegisterSoftwareDevice = 0xdead0104;
    uint32_t GetAdapterCount = 0xdead0105;
    uint32_t GetAdapterIdentifier = 0xdead0106;
    uint32_t GetAdapterModeCount = 0xdead0107;
    uint32_t EnumAdapterModes = 0xdead0108;
    uint32_t GetAdapterDisplayMode = 0xdead0109;
    uint32_t CheckDeviceType = 0xdead010a;
    uint32_t CheckDeviceFormat = 0xdead010b;
    uint32_t CheckDeviceMultiSampleType = 0xdead010c;
    uint32_t CheckDepthStencilMatch = 0xdead010d;
    uint32_t CheckDeviceFormatConversion = 0xdead010e;
    uint32_t GetDeviceCaps = 0xdead010f;
    uint32_t GetAdapterMonitor = 0xdead0110;
    uint32_t CreateDevice = 0xdead0111;

    void Init(uc_engine *uc);
};

struct ID3D9Device
{
    uint32_t vtbl;
};

struct ID3D9DeviceVtable
{
    uint32_t QueryInterface = 0xdead0201;
    uint32_t AddRef = 0xdead0202;
    uint32_t Release = 0xdead0203;
    uint32_t TestCooperativeLevel = 0xdead0204;
    uint32_t GetAvailableTextureMem = 0xdead0205;
    uint32_t EvictManagedResources = 0xdead0206;
    uint32_t GetDirect3D = 0xdead0207;
    uint32_t GetDeviceCaps = 0xdead0208;
    uint32_t GetDisplayMode = 0xdead0209;
    uint32_t GetCreationParameters = 0xdead020a;
    uint32_t SetCursorProperties = 0xdead020b;
    uint32_t SetCursorPosition = 0xdead020c;
    uint32_t ShowCursor = 0xdead020d;
    uint32_t CreateAdditionalSwapChain = 0xdead020e;
    uint32_t GetSwapChain = 0xdead020f;
    uint32_t GetNumberOfSwapChains = 0xdead0210;
    uint32_t Reset = 0xdead0211;
    uint32_t Present = 0xdead0212;
    uint32_t GetBackBuffer = 0xdead0213;
    uint32_t GetRasterStatus = 0xdead0214;
    uint32_t SetDialogBoxMode = 0xdead0215;
    uint32_t SetGammaRamp = 0xdead0216;
    uint32_t GetGammaRamp = 0xdead0217;
    uint32_t CreateTexture = 0xdead0218;
    uint32_t CreateVolumeTexture = 0xdead0219;
    uint32_t CreateCubeTexture = 0xdead021a;
    uint32_t CreateVertexBuffer = 0xdead021b;
    uint32_t CreateIndexBuffer = 0xdead021c;
    uint32_t CreateRenderTarget = 0xdead021d;
    uint32_t CreateDepthStencilSurface = 0xdead021e;
    uint32_t UpdateSurface = 0xdead021f;
    uint32_t UpdateTexture = 0xdead0220;
    uint32_t GetRenderTargetData = 0xdead0221;
    uint32_t GetFrontBufferData = 0xdead0222;
    uint32_t StretchRect = 0xdead0223;
    uint32_t ColorFill = 0xdead0224;
    uint32_t CreateOffscreenPlainSurface = 0xdead0225;
    uint32_t SetRenderTarget = 0xdead0226;
    uint32_t GetRenderTarget = 0xdead0227;
    uint32_t SetDepthStencilSurface = 0xdead0228;
    uint32_t GetDepthStencilSurface = 0xdead0229;
    uint32_t BeginScene = 0xdead022a;
    uint32_t EndScene = 0xdead022b;
    uint32_t Clear = 0xdead022c;
    uint32_t SetTransform = 0xdead022d;
    uint32_t GetTransform = 0xdead022e;
    uint32_t MultiplyTransform = 0xdead022f;
    uint32_t SetViewport = 0xdead0230;
    uint32_t GetViewport = 0xdead0231;
    uint32_t SetMaterial = 0xdead0232;
    uint32_t GetMaterial = 0xdead0233;
    uint32_t SetLight = 0xdead0234;
    uint32_t GetLight = 0xdead0235;
    uint32_t LightEnable = 0xdead0236;
    uint32_t GetLightEnable = 0xdead0237;
    uint32_t SetClipPlane = 0xdead0238;
    uint32_t GetClipPlane = 0xdead0239;
    uint32_t SetRenderState = 0xdead023a;
    uint32_t GetRenderState = 0xdead023b;
    uint32_t CreateStateBlock = 0xdead023c;
    uint32_t BeginStateBlock = 0xdead023d;
    uint32_t EndStateBlock = 0xdead023e;
    uint32_t SetClipStatus = 0xdead023f;
    uint32_t GetClipStatus = 0xdead0240;
    uint32_t GetTexture = 0xdead0241;
    uint32_t SetTexture = 0xdead0242;
    uint32_t GetTextureStageState = 0xdead0243;
    uint32_t SetTextureStageState = 0xdead0244;
    uint32_t GetSamplerState = 0xdead0245;
    uint32_t SetSamplerState = 0xdead0246;
    uint32_t ValidateDevice = 0xdead0247;
    uint32_t SetPaletteEntries = 0xdead0248;
    uint32_t GetPaletteEntries = 0xdead0249;
    uint32_t SetCurrentTexturePalette = 0xdead024a;
    uint32_t GetCurrentTexturePalette = 0xdead024b;
    uint32_t SetScissorRect = 0xdead024c;
    uint32_t GetScissorRect = 0xdead024d;
    uint32_t SetSoftwareVertexProcessing = 0xdead024e;
    uint32_t GetSoftwareVertexProcessing = 0xdead024f;
    uint32_t SetNPatchMode = 0xdead0250;
    uint32_t GetNPatchMode = 0xdead0251;
    uint32_t DrawPrimitive = 0xdead0252;
    uint32_t DrawIndexedPrimitive = 0xdead0253;
    uint32_t DrawPrimitiveUP = 0xdead0254;
    uint32_t DrawIndexedPrimitiveUP = 0xdead0255;
    uint32_t ProcessVertices = 0xdead0256;
    uint32_t CreateVertexDeclaration = 0xdead0257;
    uint32_t SetVertexDeclaration = 0xdead0258;
    uint32_t GetVertexDeclaration = 0xdead0259;
    uint32_t SetFVF = 0xdead025a;
    uint32_t GetFVF = 0xdead025b;
    uint32_t CreateVertexShader = 0xdead025c;
    uint32_t SetVertexShader = 0xdead025d;
    uint32_t GetVertexShader = 0xdead025e;
    uint32_t SetVertexShaderConstantF = 0xdead025f;
    uint32_t GetVertexShaderConstantF = 0xdead0260;
    uint32_t SetVertexShaderConstantI = 0xdead0261;
    uint32_t GetVertexShaderConstantI = 0xdead0262;
    uint32_t SetVertexShaderConstantB = 0xdead0263;
    uint32_t GetVertexShaderConstantB = 0xdead0264;
    uint32_t SetStreamSource = 0xdead0265;
    uint32_t GetStreamSource = 0xdead0266;
    uint32_t SetStreamSourceFreq = 0xdead0267;
    uint32_t GetStreamSourceFreq = 0xdead0268;
    uint32_t SetIndices = 0xdead0269;
    uint32_t GetIndices = 0xdead026a;
    uint32_t CreatePixelShader = 0xdead026b;
    uint32_t SetPixelShader = 0xdead026c;
    uint32_t GetPixelShader = 0xdead026d;
    uint32_t SetPixelShaderConstantF = 0xdead026e;
    uint32_t GetPixelShaderConstantF = 0xdead026f;
    uint32_t SetPixelShaderConstantI = 0xdead0270;
    uint32_t GetPixelShaderConstantI = 0xdead0271;
    uint32_t SetPixelShaderConstantB = 0xdead0272;
    uint32_t GetPixelShaderConstantB = 0xdead0273;
    uint32_t DrawRectPatch = 0xdead0274;
    uint32_t DrawTriPatch = 0xdead0275;
    uint32_t DeletePatch = 0xdead0276;
    uint32_t CreateQuery = 0xdead0277;

    void Init(uc_engine *uc);
};

struct ID3D9Texture
{
    uint32_t vtbl;
};

struct ID3D9TextureVtable
{
    uint32_t QueryInterface = 0xdead0301;
    uint32_t AddRef = 0xdead0302;
    uint32_t Release = 0xdead0303;
    uint32_t GetDevice = 0xdead0304;
    uint32_t SetPrivateData = 0xdead0305;
    uint32_t GetPrivateData = 0xdead0306;
    uint32_t FreePrivateData = 0xdead0307;
    uint32_t SetPriority = 0xdead0308;
    uint32_t GetPriority = 0xdead0309;
    uint32_t PreLoad = 0xdead030a;
    uint32_t GetType = 0xdead030b;
    uint32_t SetLOD = 0xdead030c;
    uint32_t GetLOD = 0xdead030d;
    uint32_t GetLevelCount = 0xdead030e;
    uint32_t SetAutoGenFilterType = 0xdead030f;
    uint32_t GetAutoGenFilterType = 0xdead0310;
    uint32_t GenerateMipSubLevels = 0xdead0311;
    uint32_t GetLevelDesc = 0xdead0312;
    uint32_t GetSurfaceLevel = 0xdead0313;
    uint32_t LockRect = 0xdead0314;
    uint32_t UnlockRect = 0xdead0315;
    uint32_t AddDirtyRect = 0xdead0316;

    uint32_t stride = 0;
    uint32_t width = 0;
    uint32_t height = 0;
    uint32_t buf = 0;
    uint32_t bufsize = 0;
    void *hostbuf = nullptr;
    sg_image image;

    void Init(uc_engine *uc);
};

struct D3DTexture
{
    ID3D9Texture tex;
    ID3D9TextureVtable vtable;
    bool used = false;
};

static constexpr unsigned texture_count = 64;

struct d3d9_mem
{
    IDInput8W idinput8;
    IDInput8WVtable idinput8_vtable;
    ID3D9 id3d9;
    ID3D9Vtable id3d9_vtable;
    ID3D9Device id3d9device;
    ID3D9DeviceVtable id3d9device_vtable;
    ID3D9XSprite id3dxsprite;
    ID3D9XSpriteVtable id3dxsprite_vtable;
    D3DTexture textures[texture_count];
    char padding[2000];

    void Init(uc_engine *uc);
};

constexpr uint32_t d3d9_mem_base = 0xf0200000;
static d3d9_mem mem;

static void cb_dinput8_IDirectInput8W_EnumDevices(uc_engine *uc, uint32_t esp)
{
    uint32_t ret = DIERR_INVALIDPARAM;
    uint32_t return_addr;

    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    esp += 24;

    ret = DI_OK;

    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_d3d9_IDirect3D9_CreateDevice(uc_engine *uc, uint32_t esp)
{
    uint32_t interface_ptr;
    uint32_t ret;
    uint32_t return_addr;

    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 28, &interface_ptr, 4));
    esp += 32;

    uint32_t dev_ptr = d3d9_mem_base + offsetof(d3d9_mem, id3d9device);
    uc_assert(uc_mem_write(uc, interface_ptr, &dev_ptr, 4));
    ret = D3D_OK;

    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_d3d9_IDirect3D9_GetAdapterDisplayMode(uc_engine *uc, uint32_t esp)
{
    uint32_t display_adapter_info_ptr;
    uint32_t ret = D3DERR_INVALIDCALL;
    uint32_t return_addr;

    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 12, &display_adapter_info_ptr, 4));
    esp += 16;

    if (display_adapter_info_ptr != 0)
    {
        const uint32_t width = 570;
        uc_assert(uc_mem_write(uc, display_adapter_info_ptr, &width, 4));
        const uint32_t height = 320;
        uc_assert(uc_mem_write(uc, display_adapter_info_ptr + 4, &height, 4));
        const uint32_t refresh_rate = 60;
        uc_assert(uc_mem_write(uc, display_adapter_info_ptr + 8, &refresh_rate, 4));
        const uint32_t d3d_format = 22; // D3DFMT_X8R8G8B8
        uc_assert(uc_mem_write(uc, display_adapter_info_ptr + 12, &d3d_format, 4));
        ret = D3D_OK;
    }

    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_d3d9_IDirect3DDevice9_Reset(uc_engine *uc, uint32_t esp)
{
    uint32_t buffer_info;
    uint32_t ret = D3DERR_INVALIDCALL;
    uint32_t return_addr;

    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 8, &buffer_info, 4));
    esp += 12;

    if (buffer_info != 0)
    {
        int32_t width = 0;
        int32_t height = 0;
        uc_assert(uc_mem_read(uc, buffer_info, &width, 4));
        uc_assert(uc_mem_read(uc, buffer_info + 4, &height, 4));

        logf("D3D Reset, framebuffer size: %ux%u\n", width, height);
        window_width = width;
        window_height = height;

        ret = D3D_OK;
    }

    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_d3d9_IDirect3DDevice9_TestCooperativeLevel(uc_engine *uc, uint32_t esp)
{
    uint32_t buffer_info;
    uint32_t ret = D3D_OK;
    uint32_t return_addr;

    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    esp += 8;

    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static bool sgl_initialized = false;

static void cb_d3d9_IDirect3DDevice9_BeginScene(uc_engine *uc, uint32_t esp)
{
    uint32_t buffer_info;
    uint32_t ret = D3D_OK;
    uint32_t return_addr;
    emu_nointerrupt = true;

    if (!sgl_initialized)
    {
        sgl_initialized = true;
        sgl_enable_texture();
        sgl_ortho(0.0, 800.0, 480.0, 0.0, -1000.0, 1000.0);
    }

    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    esp += 8;

    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_d3d9_IDirect3DDevice9_EndScene(uc_engine *uc, uint32_t esp)
{
    uint32_t buffer_info;
    uint32_t ret = D3D_OK;
    uint32_t return_addr;
    emu_nointerrupt = false;

    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    esp += 8;

    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_d3d9_IDirect3DDevice9_Present(uc_engine *uc, uint32_t esp)
{
    uint32_t buffer_info;
    uint32_t ret = D3D_OK;
    uint32_t return_addr;
    emu_nointerrupt = false;

    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    esp += 20;
    if (sgl_initialized)
    {
        sgl_initialized = false;
    }

    uc_assert(uc_emu_stop(uc));
    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_d3d9_IDirect3D9Texture_LockRect(uc_engine *uc, uint32_t esp)
{
    uint32_t self;
    uint32_t level;
    uint32_t rect;
    uint32_t ret = D3DERR_INVALIDCALL;
    uint32_t return_addr;

    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &self, 4));
    uc_assert(uc_mem_read(uc, esp + 8, &level, 4));
    uc_assert(uc_mem_read(uc, esp + 12, &rect, 4));
    esp += 24;

    auto tex = reinterpret_cast<D3DTexture *>(uintptr_t(&mem) + uintptr_t(self) - uintptr_t(d3d9_mem_base));
    logf("lock width=%d height=%d\n", tex->vtable.width, tex->vtable.height);
    if (level == 0 && rect != 0 && tex->vtable.buf != 0)
    {
        uc_assert(uc_mem_write(uc, rect, &tex->vtable.stride, 4));
        uc_assert(uc_mem_write(uc, rect + 4, &tex->vtable.buf, 4));
        ret = D3D_OK;
    }

    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_d3d9_IDirect3D9Texture_UnlockRect(uc_engine *uc, uint32_t esp)
{
    uint32_t self;
    uint32_t level;
    uint32_t ret = D3DERR_INVALIDCALL;
    uint32_t return_addr;

    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &self, 4));
    uc_assert(uc_mem_read(uc, esp + 8, &level, 4));
    esp += 12;

    auto tex = reinterpret_cast<D3DTexture *>(uintptr_t(&mem) + uintptr_t(self) - uintptr_t(d3d9_mem_base));
    if (level == 0 && tex->vtable.buf != 0)
    {
        sg_image_data im_data;
        im_data.subimage[0][0].ptr = tex->vtable.hostbuf;
        im_data.subimage[0][0].size = tex->vtable.bufsize;

        auto buf = reinterpret_cast<uint8_t *>(tex->vtable.hostbuf);

        for (int i = 0; i < tex->vtable.bufsize; i += 4)
        {
            std::swap(buf[i], buf[i + 2]);
        }

        sg_update_image(tex->vtable.image, im_data);
        ret = D3D_OK;
    }

    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_d3d9_IDirect3D9Texture_Release(uc_engine *uc, uint32_t esp)
{
    uint32_t self;
    uint32_t ret = D3DERR_INVALIDCALL;
    uint32_t return_addr;

    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &self, 4));
    esp += 8;

    auto tex = reinterpret_cast<D3DTexture *>(uintptr_t(&mem) + uintptr_t(self) - uintptr_t(d3d9_mem_base));
    if (self != 0 && tex->used)
    {
        tex->used = false;
        sg_destroy_image(tex->vtable.image);
        tex->vtable.image.id = 0;

        if (tex->vtable.hostbuf != nullptr)
        {
            kernel32_host_free(tex->vtable.hostbuf);
            tex->vtable.hostbuf = nullptr;
        }

        tex->vtable.buf = 0;
        tex->vtable.bufsize = 0;
        tex->vtable.width = 0;
        tex->vtable.height = 0;
        tex->vtable.stride = 0;

        ret = D3D_OK;
    }

    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_d3d9_ID3DXSprite9_Release(uc_engine *uc, uint32_t esp)
{
    uint32_t self;
    uint32_t ret = D3D_OK;
    uint32_t return_addr;

    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 4, &self, 4));
    esp += 8;

    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_d3d9_ID3DXSprite9_Begin(uc_engine *uc, uint32_t esp)
{
    uint32_t self;
    uint32_t ret = D3D_OK;
    uint32_t return_addr;

    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    esp += 12;

    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_d3d9_ID3DXSprite9_End(uc_engine *uc, uint32_t esp)
{
    uint32_t self;
    uint32_t ret = D3D_OK;
    uint32_t return_addr;

    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    esp += 8;

    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_d3d9_ID3DXSprite9_Draw(uc_engine *uc, uint32_t esp)
{
    uint32_t texture_addr;
    uint32_t rect_addr;
    uint32_t position_addr;
    uint32_t color;
    int rect[4];
    float pos[3];

    uint32_t ret = D3D_OK;
    uint32_t return_addr;

    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 8, &texture_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 12, &rect_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 20, &position_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 24, &color, 4));
    // logf("Draw: %#010x %#010x %#010x %#010x\n", texture_addr, rect_addr, position_addr, color);
    esp += 28;

    auto tex = reinterpret_cast<D3DTexture *>(uintptr_t(&mem) + uintptr_t(texture_addr) - uintptr_t(d3d9_mem_base));

    uc_assert(uc_mem_read(uc, position_addr, &pos, 12));
    if (rect_addr != 0)
    {
        uc_assert(uc_mem_read(uc, rect_addr, &rect, 16));
    }
    else
    {
        rect[0] = 0;
        rect[1] = 0;
        rect[2] = tex->vtable.width;
        rect[3] = tex->vtable.height;
    }

    if (tex->used)
    {
        sgl_texture(tex->vtable.image);
        sgl_begin_quads();
        sgl_c1i(color);
        sgl_v3f_t2f(pos[0], pos[1] + (rect[3] - rect[1]), pos[2], float(rect[0]) / float(tex->vtable.width), float(rect[3]) / float(tex->vtable.height));
        sgl_v3f_t2f(pos[0] + (rect[2] - rect[0]), pos[1] + (rect[3] - rect[1]), pos[2], float(rect[2]) / float(tex->vtable.width), float(rect[3]) / float(tex->vtable.height));
        sgl_v3f_t2f(pos[0] + (rect[2] - rect[0]), pos[1], pos[2], float(rect[2]) / float(tex->vtable.width), float(rect[1]) / float(tex->vtable.height));
        sgl_v3f_t2f(pos[0], pos[1], pos[2], float(rect[0]) / float(tex->vtable.width), float(rect[1]) / float(tex->vtable.height));
        sgl_end();
    }

    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_dinput8_DirectInput8Create(uc_engine *uc, uint32_t esp)
{
    uint32_t target;
    uint32_t ret;
    uint32_t return_addr;

    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 16, &target, 4));
    esp += 24;

    if (target != 0)
    {
        uint32_t addr = d3d9_mem_base + offsetof(d3d9_mem, idinput8);
        uc_assert(uc_mem_write(uc, target, &addr, 4));
        ret = 0;
    }

    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_d3d9_Direct3DCreate9(uc_engine *uc, uint32_t esp)
{
    uint32_t ret;
    uint32_t return_addr;

    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    esp += 8;

    ret = d3d9_mem_base + offsetof(d3d9_mem, id3d9);

    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_d3d9_D3DXCreateSprite(uc_engine *uc, uint32_t esp)
{
    uint32_t spr_ptr;
    uint32_t ret;
    uint32_t return_addr;

    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 8, &spr_ptr, 4));
    esp += 12;

    if (spr_ptr != 0)
    {
        uint32_t addr = d3d9_mem_base + offsetof(d3d9_mem, id3dxsprite);
        uc_assert(uc_mem_write(uc, spr_ptr, &addr, 4));
    }

    ret = 0;

    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_d3d9_D3DXCreateFontA(uc_engine *uc, uint32_t esp)
{
    uint32_t ret;
    uint32_t return_addr;

    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    esp += 52;

    ret = 0;

    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_d3d9_D3DXCreateFontW(uc_engine *uc, uint32_t esp)
{
    uint32_t ret;
    uint32_t return_addr;

    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    esp += 52;

    ret = 0;

    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

static void cb_d3d9_D3DXCreateTexture(uc_engine *uc, uint32_t esp)
{
    int width;
    int height;
    uint32_t usage;
    uint32_t pixel_format;
    uint32_t tex_ptr;
    uint32_t ret = D3DERR_INVALIDCALL;
    uint32_t return_addr;

    uc_assert(uc_mem_read(uc, esp, &return_addr, 4));
    uc_assert(uc_mem_read(uc, esp + 8, &width, 4));
    uc_assert(uc_mem_read(uc, esp + 12, &height, 4));
    uc_assert(uc_mem_read(uc, esp + 20, &usage, 4));
    uc_assert(uc_mem_read(uc, esp + 24, &pixel_format, 4));
    uc_assert(uc_mem_read(uc, esp + 32, &tex_ptr, 4));
    esp += 36;

    if (width > 0 && height > 0 && pixel_format == 21 && tex_ptr != 0)
    {
        bool tex_found = false;

        for (int i = 0; i < texture_count; i++)
        {
            auto &tex = mem.textures[i];
            if (tex.used)
                continue;

            tex_found = true;

            sg_image_desc img_desc = {
                .render_target = false,
                .width = width,
                .height = height,
                .usage = SG_USAGE_DYNAMIC,
                .pixel_format = SG_PIXELFORMAT_RGBA8,
                .min_filter = SG_FILTER_NEAREST,
                .mag_filter = SG_FILTER_NEAREST,
            };

            uintptr_t bufaddr;
            uint32_t bufsize = width * height * 4;
            tex.used = true;
            tex.vtable.hostbuf = kernel32_host_malloc(&bufaddr, bufsize);
            tex.vtable.buf = bufaddr;
            tex.vtable.bufsize = bufsize;

            memset(tex.vtable.hostbuf, 0xff, bufsize);
            // img_desc.data.subimage[0][0].ptr = tex.vtable.hostbuf;
            // img_desc.data.subimage[0][0].size = bufsize;

            tex.vtable.image = sg_make_image(&img_desc);
            tex.vtable.stride = width * 4;
            tex.vtable.width = width;
            tex.vtable.height = height;

            uint32_t addr = d3d9_mem_base + (uint64_t(&tex) - uint64_t(&mem));
            tex.tex.vtbl = addr + offsetof(D3DTexture, vtable);

            uc_assert(uc_mem_write(uc, tex_ptr, &addr, 4));
            ret = D3D_OK;

            logf("Texture ID: %d w=%d h=%d addr=%#010x ret=%#010x\n", i, width, height, addr, ret);
            break;
        }

        if (!tex_found)
            ret = D3DERR_OUTOFVIDEOMEMORY;
    }

    uc_assert(uc_reg_write(uc, UC_X86_REG_ESP, &esp));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EAX, &ret));
    uc_assert(uc_reg_write(uc, UC_X86_REG_EIP, &return_addr));
}

void d3d9_mem::Init(uc_engine *uc)
{
    mem.idinput8.vtbl = d3d9_mem_base + offsetof(d3d9_mem, idinput8_vtable);
    mem.idinput8_vtable.Init(uc);

    mem.id3d9.vtbl = d3d9_mem_base + offsetof(d3d9_mem, id3d9_vtable);
    mem.id3d9_vtable.Init(uc);

    mem.id3d9device.vtbl = d3d9_mem_base + offsetof(d3d9_mem, id3d9device_vtable);
    mem.id3d9device_vtable.Init(uc);

    mem.id3dxsprite.vtbl = d3d9_mem_base + offsetof(d3d9_mem, id3dxsprite_vtable);
    mem.id3dxsprite_vtable.Init(uc);

    for (int i = 0; i < texture_count; i++)
    {
        mem.textures[i].vtable.Init(uc);
    }
}

void IDInput8WVtable::Init(uc_engine *uc)
{
    EnumDevices = add_syscall(uc, thunk_cbs.size(), cb_dinput8_IDirectInput8W_EnumDevices);
}

void ID3D9Vtable::Init(uc_engine *uc)
{
    CreateDevice = add_syscall(uc, thunk_cbs.size(), cb_d3d9_IDirect3D9_CreateDevice);
    GetAdapterDisplayMode = add_syscall(uc, thunk_cbs.size(), cb_d3d9_IDirect3D9_GetAdapterDisplayMode);
}

void ID3D9DeviceVtable::Init(uc_engine *uc)
{
    Reset = add_syscall(uc, thunk_cbs.size(), cb_d3d9_IDirect3DDevice9_Reset);
    TestCooperativeLevel = add_syscall(uc, thunk_cbs.size(), cb_d3d9_IDirect3DDevice9_TestCooperativeLevel);
    BeginScene = add_syscall(uc, thunk_cbs.size(), cb_d3d9_IDirect3DDevice9_BeginScene);
    EndScene = add_syscall(uc, thunk_cbs.size(), cb_d3d9_IDirect3DDevice9_EndScene);
    Present = add_syscall(uc, thunk_cbs.size(), cb_d3d9_IDirect3DDevice9_Present);
}

void ID3D9TextureVtable::Init(uc_engine *uc)
{
    Release = add_syscall(uc, thunk_cbs.size(), cb_d3d9_IDirect3D9Texture_Release);
    LockRect = add_syscall(uc, thunk_cbs.size(), cb_d3d9_IDirect3D9Texture_LockRect);
    UnlockRect = add_syscall(uc, thunk_cbs.size(), cb_d3d9_IDirect3D9Texture_UnlockRect);
}

void ID3D9XSpriteVtable::Init(uc_engine *uc)
{
    Release = add_syscall(uc, thunk_cbs.size(), cb_d3d9_ID3DXSprite9_Release);
    Begin = add_syscall(uc, thunk_cbs.size(), cb_d3d9_ID3DXSprite9_Begin);
    End = add_syscall(uc, thunk_cbs.size(), cb_d3d9_ID3DXSprite9_End);
    Draw = add_syscall(uc, thunk_cbs.size(), cb_d3d9_ID3DXSprite9_Draw);
}

void test_draw()
{
    /*sgl_defaults();
    sgl_load_pipeline(state.deflt.pip);

    sgl_enable_texture();
    sgl_ortho(0.0, 800.0, 480.0, 0.0, -300.0, 300.0);

    for (int i = 0; i < texture_count; i++)
    {
        if (mem.textures[i].used)
        {
            sgl_texture(mem.textures[i].vtable.image);

            sgl_begin_quads();
            sgl_c3b(255, 255, 255);
            sgl_v3f_t2f(0.0f, 1.0f, 0.0f, 0.0f, 1.0f);
            sgl_v3f_t2f(1.0f, 1.0f, 0.0f, 1.0f, 1.0f);
            sgl_v3f_t2f(1.0f, 0.0f, 0.0f, 1.0f, 0.0f);
            sgl_v3f_t2f(0.0f, 0.0f, 0.0f, 0.0f, 0.0f);
            sgl_end();
        }
    }

    sgl_draw();*/
}

void install_d3d9_exports(uc_engine *uc)
{
    uc_assert(uc_mem_map_ptr(uc, d3d9_mem_base, align_address(sizeof(d3d9_mem)), UC_PROT_READ | UC_PROT_WRITE, &mem));
    mem.Init(uc);

    Export DirectInput8Create_ex = {"DirectInput8Create", cb_dinput8_DirectInput8Create};
    exports["DirectInput8Create"] = DirectInput8Create_ex;

    Export Direct3DCreate9_ex = {"Direct3DCreate9", cb_d3d9_Direct3DCreate9};
    exports["Direct3DCreate9"] = Direct3DCreate9_ex;

    Export D3DXCreateSprite_ex = {"D3DXCreateSprite", cb_d3d9_D3DXCreateSprite};
    exports["D3DXCreateSprite"] = D3DXCreateSprite_ex;

    Export D3DXCreateFontA_ex = {"D3DXCreateFontA", cb_d3d9_D3DXCreateFontA};
    exports["D3DXCreateFontA"] = D3DXCreateFontA_ex;

    Export D3DXCreateFontW_ex = {"D3DXCreateFontW", cb_d3d9_D3DXCreateFontW};
    exports["D3DXCreateFontW"] = D3DXCreateFontW_ex;

    Export D3DXCreateTexture_ex = {"D3DXCreateTexture", cb_d3d9_D3DXCreateTexture};
    exports["D3DXCreateTexture"] = D3DXCreateTexture_ex;
}