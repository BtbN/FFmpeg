/*
 * This file is part of FFmpeg.
 *
 * FFmpeg is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * FFmpeg is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with FFmpeg; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "config.h"

#if !defined(_WIN32_WINNT) || _WIN32_WINNT < 0x0A00
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif

#include <windows.h>
#include <winstring.h>
#include <roapi.h>
#include <dwmapi.h>

#define COBJMACROS
#define WIDL_using_Windows_Graphics_Capture
#include <initguid.h>
#include <d3d11.h>
#include <windows.graphics.capture.h>
#include <windows.graphics.capture.interop.h>

#include "libavutil/avassert.h"
#include "libavutil/internal.h"
#include "libavutil/mem.h"
#include "libavutil/opt.h"
#include "libavutil/time.h"
#include "libavutil/pixdesc.h"
#include "libavutil/hwcontext.h"
#include "libavutil/hwcontext_d3d11va.h"
#include "compat/w32dlfcn.h"
#include "avfilter.h"
#include "filters.h"
#include "video.h"

#define TIMER_RES 1000000
#define TIMER_RES64 INT64_C(1000000)

typedef struct GfxCaptureFunctions {
    void *combase_handle;
    void *dwmapi_handle;

    HRESULT (WINAPI *RoInitialize)(RO_INIT_TYPE initType);
    void (WINAPI *RoUninitialize)(void);
    HRESULT (WINAPI *RoGetActivationFactory)(HSTRING activatableClassId, REFIID iid, void **factory);
    HRESULT (WINAPI *WindowsCreateStringReference)(PCWSTR sourceString, UINT32 length, HSTRING_HEADER *hstringHeader, HSTRING *string);

    HRESULT (WINAPI *DwmGetWindowAttribute)(HWND hwnd, DWORD dwAttribute, PVOID pvAttribute, DWORD cbAttribute);
} GfxCaptureFunctions;

typedef struct GfxCaptureContext {
    const AVClass *class;

    AVBufferRef *device_ref;
    AVHWDeviceContext *device_ctx;
    AVD3D11VADeviceContext *device_hwctx;

    AVBufferRef *frames_ref;
    AVHWFramesContext *frames_ctx;
    AVD3D11VAFramesContext *frames_hwctx;

    D3D11_BOX client_box;
    int width;
    int height;

    GfxCaptureFunctions fn;

    HWND capture_hwnd;
    IGraphicsCaptureItemInterop *capture_item_interop;

    const char *window_name;
    int capture_cursor;
    AVRational frame_rate;
} GfxCaptureContext;

#define OFFSET(x) offsetof(GfxCaptureContext, x)
#define FLAGS AV_OPT_FLAG_VIDEO_PARAM|AV_OPT_FLAG_FILTERING_PARAM
static const AVOption gfxcapture_options[] = {
    { "window_name",    "name of the window to capture", OFFSET(window_name),    AV_OPT_TYPE_STRING,     { .str = NULL },  0, INT_MAX, FLAGS },
    { "capture_cursor", "capture mouse cursor",          OFFSET(capture_cursor), AV_OPT_TYPE_BOOL,       { .i64 = 1 },     0,       1, FLAGS },
    { "framerate",      "set video frame rate",          OFFSET(frame_rate),      AV_OPT_TYPE_VIDEO_RATE, { .str = "30" },  0, INT_MAX, FLAGS },
    { NULL }
};

AVFILTER_DEFINE_CLASS(gfxcapture);

static BOOL CALLBACK enum_capture_windows(HWND hwnd, LPARAM lParam)
{
    AVFilterContext *avctx = (AVFilterContext*)lParam;
    GfxCaptureContext *ctx = avctx->priv;

    char window_text[512];
    int text_length = GetWindowTextA(hwnd, window_text, FF_ARRAY_ELEMS(window_text));
    if (text_length == 0)
        return TRUE;

    // TODO: more sophisticated matching
    if (strstr(window_text, ctx->window_name) != NULL) {
        av_log(avctx, AV_LOG_DEBUG, "Found capture window: %s\n", window_text);
        ctx->capture_hwnd = hwnd;
        return FALSE;
    }

    return TRUE;
}

static int find_capture_window(AVFilterContext *avctx)
{
    GfxCaptureContext *ctx = avctx->priv;

    ctx->capture_hwnd = NULL;
    if (EnumWindows(enum_capture_windows, (LPARAM)avctx) || !ctx->capture_hwnd)
        return AVERROR(ENOENT);

    return 0;
}

static int update_dimensions_from_hwnd(AVFilterContext *avctx)
{
    GfxCaptureContext *ctx = avctx->priv;
    RECT client_rect = { 0 }, window_rect = { 0 };
    POINT upper_left = { 0 };

    av_assert0(ctx->fn.DwmGetWindowAttribute);

    if (!ctx->capture_hwnd)
        return AVERROR(ENOENT);

    if (!GetClientRect(ctx->capture_hwnd, &client_rect)) {
        av_log(avctx, AV_LOG_ERROR, "GetClientRect failed\n");
        return AVERROR_EXTERNAL;
    }

    if (FAILED(ctx->fn.DwmGetWindowAttribute(ctx->capture_hwnd, DWMWA_EXTENDED_FRAME_BOUNDS, &window_rect, sizeof(window_rect)))) {
        av_log(avctx, AV_LOG_ERROR, "DwmGetWindowAttribute failed\n");
        return AVERROR_EXTERNAL;
    }

    if (!ClientToScreen(ctx->capture_hwnd, &upper_left)) {
        av_log(avctx, AV_LOG_ERROR, "ClientToScreen failed\n");
        return AVERROR_EXTERNAL;
    }

    ctx->client_box.left = FFMAX(upper_left.x - window_rect.left, 0);
    ctx->client_box.top = FFMAX(upper_left.y - window_rect.top, 0);

    ctx->width = FFMIN(client_rect.right - client_rect.left - ctx->client_box.left, client_rect.right - client_rect.left);
    ctx->height = FFMIN(client_rect.bottom - client_rect.top - ctx->client_box.top, client_rect.bottom - client_rect.top);

    ctx->client_box.right = ctx->client_box.left + ctx->width;
    ctx->client_box.bottom = ctx->client_box.top + ctx->height;

    ctx->client_box.front = 0;
    ctx->client_box.back = 1;

    av_log(avctx, AV_LOG_DEBUG, "Window rect: %ld,%ld - %ld,%ld\n", window_rect.left, window_rect.top, window_rect.right, window_rect.bottom);
    av_log(avctx, AV_LOG_DEBUG, "Client rect: %ld,%ld - %ld,%ld\n", client_rect.left, client_rect.top, client_rect.right, client_rect.bottom);
    av_log(avctx, AV_LOG_DEBUG, "Upper left: %ld,%ld\n", upper_left.x, upper_left.y);
    av_log(avctx, AV_LOG_DEBUG, "Capture box: left=%d top=%d right=%d bottom=%d\n", ctx->client_box.left, ctx->client_box.top, ctx->client_box.right, ctx->client_box.bottom);
    av_log(avctx, AV_LOG_DEBUG, "Capture dimensions: %d x %d\n", ctx->width, ctx->height);

    return 0;
}

static int init_gfxcapture_session(AVFilterContext *avctx)
{
    GfxCaptureContext *ctx = avctx->priv;
    IDXGIDevice *dxgi_device = NULL;
    HSTRING_HEADER hsheader = { 0 };
    HSTRING hs = NULL;
    HRESULT hr;

    av_assert0(ctx->fn.RoGetActivationFactory);
    av_assert0(ctx->fn.WindowsCreateStringReference);
    av_assert0(ctx->device_hwctx);
    av_assert0(ctx->device_hwctx->device);

    hr = ID3D11Device_QueryInterface(ctx->device_hwctx->device, &IID_IDXGIDevice, (void**)&dxgi_device);
    if (FAILED(hr)) {
        av_log(avctx, AV_LOG_ERROR, "Failed querying IDXGIDevice\n");
        return AVERROR_EXTERNAL;
    }

    PCWSTR itemName = RuntimeClass_Windows_Graphics_Capture_GraphicsCaptureItem;
    hr = ctx->fn.WindowsCreateStringReference(itemName, (UINT32)wcslen(itemName), &hsheader, &hs);
    if (FAILED(hr)) {
        av_log(avctx, AV_LOG_ERROR, "Failed to create string reference\n");
        return AVERROR_EXTERNAL;
    }

    IGraphicsCaptureItemInterop *interop = NULL;
    hr = ctx->fn.RoGetActivationFactory(hs, &IID_IGraphicsCaptureItemInterop, (void**)&interop);
    if (FAILED(hr)) {
        av_log(avctx, AV_LOG_ERROR, "Failed to get activation factory: 0x%08lX\n", hr);
        return AVERROR_EXTERNAL;
    }

    IGraphicsCaptureItemInterop_Release(interop);
    IDXGIDevice_Release(dxgi_device);

    return 0;
}

static av_cold void gfxcapture_uninit(AVFilterContext *avctx)
{
    GfxCaptureContext *ctx = avctx->priv;

    if (ctx->fn.RoUninitialize)
        ctx->fn.RoUninitialize();

    if (ctx->fn.combase_handle)
        dlclose(ctx->fn.combase_handle);
    if (ctx->fn.dwmapi_handle)
        dlclose(ctx->fn.dwmapi_handle);
    memset(&ctx->fn, 0, sizeof(ctx->fn));
}

static av_cold int load_functions(AVFilterContext *avctx)
{
    GfxCaptureContext *ctx = avctx->priv;

    ctx->fn.combase_handle = dlopen("combase.dll", 0);
    if (!ctx->fn.combase_handle) {
        av_log(avctx, AV_LOG_ERROR, "Failed opening combase.dll\n");
        return AVERROR(ENOSYS);
    }

    ctx->fn.dwmapi_handle = dlopen("dwmapi.dll", 0);
    if (!ctx->fn.dwmapi_handle) {
        av_log(avctx, AV_LOG_ERROR, "Failed opening dwmapi.dll\n");
        return AVERROR(ENOSYS);
    }

#define LOAD_FUNC(handle, name) \
    ctx->fn.name = (void*)dlsym(handle, #name); \
    if (!ctx->fn.name) { \
        av_log(avctx, AV_LOG_ERROR, "Failed loading " #name "\n"); \
        return AVERROR(ENOSYS); \
    }

    LOAD_FUNC(ctx->fn.combase_handle, RoInitialize);
    LOAD_FUNC(ctx->fn.combase_handle, RoUninitialize);
    LOAD_FUNC(ctx->fn.combase_handle, RoGetActivationFactory);
    LOAD_FUNC(ctx->fn.combase_handle, WindowsCreateStringReference);

    LOAD_FUNC(ctx->fn.dwmapi_handle, DwmGetWindowAttribute);

#undef LOAD_FUNC
    return 0;
}

static av_cold int gfxcapture_init(AVFilterContext *avctx)
{
    GfxCaptureContext *ctx = avctx->priv;
    int ret = 0;

    ret = load_functions(avctx);
    if (ret < 0) {
        ctx->fn.RoUninitialize = NULL;
        goto fail;
    }

    if (FAILED(ctx->fn.RoInitialize(RO_INIT_MULTITHREADED))) {
        av_log(avctx, AV_LOG_ERROR, "Failed to initialize WinRT COM library\n");
        ctx->fn.RoUninitialize = NULL;
        ret = AVERROR_EXTERNAL;
        goto fail;
    }

    ret = find_capture_window(avctx);
    if (ret < 0) {
        av_log(avctx, AV_LOG_ERROR, "Failed to find window\n");
        goto fail;
    }

    ret = update_dimensions_from_hwnd(avctx);
    if (ret < 0) {
        av_log(avctx, AV_LOG_ERROR, "Failed to get window dimensions\n");
        goto fail;
    }

    av_log(avctx, AV_LOG_DEBUG, "gfxcapture source initialized successfully\n");

    return 0;

fail:
    gfxcapture_uninit(avctx);
    return ret;
}

static av_cold int init_hwframes_ctx(AVFilterContext *avctx)
{
    GfxCaptureContext *ctx = avctx->priv;
    int ret = 0;

    ctx->frames_ref = av_hwframe_ctx_alloc(ctx->device_ref);
    if (!ctx->frames_ref)
        return AVERROR(ENOMEM);
    ctx->frames_ctx = (AVHWFramesContext*)ctx->frames_ref->data;
    ctx->frames_hwctx = (AVD3D11VAFramesContext*)ctx->frames_ctx->hwctx;

    ctx->frames_ctx->format    = AV_PIX_FMT_D3D11;
    ctx->frames_ctx->width     = ctx->width;
    ctx->frames_ctx->height    = ctx->height;
    ctx->frames_ctx->sw_format = AV_PIX_FMT_BGRA; //TODO: more?

    ret = av_hwframe_ctx_init(ctx->frames_ref);
    if (ret < 0) {
        av_log(avctx, AV_LOG_ERROR, "Failed to initialise hardware frames context: %d.\n", ret);
        goto fail;
    }

    return 0;
fail:
    av_buffer_unref(&ctx->frames_ref);
    return ret;
}

static int gfxcapture_config_props(AVFilterLink *outlink)
{
    AVFilterContext *avctx = outlink->src;
    GfxCaptureContext *ctx = avctx->priv;
    FilterLink *link = ff_filter_link(outlink);
    int ret;

    if (avctx->hw_device_ctx) {
        ctx->device_ctx = (AVHWDeviceContext*)avctx->hw_device_ctx->data;

        if (ctx->device_ctx->type != AV_HWDEVICE_TYPE_D3D11VA) {
            av_log(avctx, AV_LOG_ERROR, "Non-D3D11VA input hw_device_ctx\n");
            return AVERROR(EINVAL);
        }

        ctx->device_ref = av_buffer_ref(avctx->hw_device_ctx);
        if (!ctx->device_ref)
            return AVERROR(ENOMEM);

        av_log(avctx, AV_LOG_VERBOSE, "Using provided hw_device_ctx\n");
    } else {
        ret = av_hwdevice_ctx_create(&ctx->device_ref, AV_HWDEVICE_TYPE_D3D11VA, NULL, NULL, 0);
        if (ret < 0) {
            av_log(avctx, AV_LOG_ERROR, "Failed to create D3D11VA device.\n");
            return ret;
        }

        ctx->device_ctx = (AVHWDeviceContext*)ctx->device_ref->data;

        av_log(avctx, AV_LOG_VERBOSE, "Created internal hw_device_ctx\n");
    }

    ctx->device_hwctx = (AVD3D11VADeviceContext*)ctx->device_ctx->hwctx;

    ret = init_hwframes_ctx(avctx);
    if (ret < 0)
        return ret;

    ret = init_gfxcapture_session(avctx);
    if (ret < 0) {
        av_log(avctx, AV_LOG_ERROR, "Failed to initialize graphics capture session\n");
        return ret;
    }

    link->hw_frames_ctx = av_buffer_ref(ctx->frames_ref);
    if (!link->hw_frames_ctx)
        return AVERROR(ENOMEM);

    outlink->w = ctx->width;
    outlink->h = ctx->height;
    outlink->time_base = (AVRational){1, TIMER_RES};
    link->frame_rate = ctx->frame_rate;

    return 0;
}

static int gfxcapture_request_frame(AVFilterLink *outlink)
{
    AVFilterContext *avctx = outlink->src;
    GfxCaptureContext *ctx = avctx->priv;
    AVFrame *frame = NULL;
    int ret = AVERROR_BUG;

    return ret;
    //return ff_filter_frame(outlink, frame);
}

static const AVFilterPad gfxcapture_outputs[] = {
    {
        .name          = "default",
        .type          = AVMEDIA_TYPE_VIDEO,
        .request_frame = gfxcapture_request_frame,
        .config_props  = gfxcapture_config_props,
    },
};

const FFFilter ff_vsrc_gfxcapture = {
    .p.name        = "gfxcapture",
    .p.description = NULL_IF_CONFIG_SMALL("Capture graphics/screen content as a video source"),
    .p.priv_class  = &gfxcapture_class,
    .p.inputs      = NULL,
    .p.flags       = AVFILTER_FLAG_HWDEVICE,
    .priv_size     = sizeof(GfxCaptureContext),
    .init          = gfxcapture_init,
    .uninit        = gfxcapture_uninit,
    FILTER_OUTPUTS(gfxcapture_outputs),
    FILTER_SINGLE_PIXFMT(AV_PIX_FMT_D3D11),
    .flags_internal = FF_FILTER_FLAG_HWFRAME_AWARE,
};
