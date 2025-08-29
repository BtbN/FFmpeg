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

extern "C" {
#include "config.h"
}

#if !defined(_WIN32_WINNT) || _WIN32_WINNT < 0x0A00
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif

#define WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION 0x130000

// work around bug in mingw double-defining IReference<unsigned char> (BYTE == boolean)
#define ____FIReference_1_boolean_INTERFACE_DEFINED__

#include <windows.h>
#include <initguid.h>
#include <wrl.h>
#include <roapi.h>
#include <dwmapi.h>
#include <d3d11.h>
#include <d3dcompiler.h>
#include <dispatcherqueue.h>
#include <windows.foundation.h>
#include <windows.graphics.capture.h>
#include <windows.graphics.capture.interop.h>
#include <windows.graphics.directx.direct3d11.h>
#if HAVE_IDIRECT3DDXGIINTERFACEACCESS
#include <windows.graphics.directx.direct3d11.interop.h>
#endif

extern "C" {
#include "libavutil/avassert.h"
#include "libavutil/internal.h"
#include "libavutil/mem.h"
#include "libavutil/opt.h"
#include "libavutil/time.h"
#include "libavutil/pixdesc.h"
#include "libavutil/hwcontext.h"
#include "libavutil/hwcontext_d3d11va.h"
#include "avfilter.h"
#include "filters.h"
#include "video.h"

#include "vsrc_gfxcapture.h"
}

#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

#include "vsrc_gfxcapture_winrt.h"

using namespace ABI::Windows::System;
using namespace ABI::Windows::Foundation;
using namespace ABI::Windows::Graphics::Capture;
using namespace ABI::Windows::Graphics::DirectX::Direct3D11;
using namespace Windows::Graphics::DirectX::Direct3D11;
using Microsoft::WRL::ComPtr;
using ABI::Windows::Graphics::SizeInt32;
using ABI::Windows::Foundation::TimeSpan;
using ABI::Windows::Graphics::DirectX::DirectXPixelFormat;

#define TIMESPAN_RES 10000000
#define TIMESPAN_RES64 INT64_C(10000000)

#define CAPTURE_POOL_SIZE 2

enum {
    WM_RT_THREAD_SHUTDOWN = WM_APP + 1,
    WM_RT_SHUTDOWN_DONE = WM_APP + 2
};

#define CCTX(ctx) static_cast<GfxCaptureContext*>(ctx)

typedef struct GfxCaptureFunctions {
    hmodule_ptr_t graphicscapture_handle;

    hmodule_ptr_t combase_handle;
    HRESULT (WINAPI *RoInitialize)(RO_INIT_TYPE initType);
    void (WINAPI *RoUninitialize)(void);
    HRESULT (WINAPI *RoGetActivationFactory)(HSTRING activatableClassId, REFIID iid, void **factory);
    HRESULT (WINAPI *WindowsCreateStringReference)(PCWSTR sourceString, UINT32 length, HSTRING_HEADER *hstringHeader, HSTRING *string);

    hmodule_ptr_t dwmapi_handle;
    HRESULT (WINAPI *DwmGetWindowAttribute)(HWND hwnd, DWORD dwAttribute, PVOID pvAttribute, DWORD cbAttribute);

    hmodule_ptr_t d3d11_handle;
    HRESULT (WINAPI *CreateDirect3D11DeviceFromDXGIDevice)(IDXGIDevice *dxgiDevice, IInspectable **graphicsDevice);

    hmodule_ptr_t coremsg_handle;
    HRESULT (WINAPI *CreateDispatcherQueueController)(DispatcherQueueOptions options, PDISPATCHERQUEUECONTROLLER *dispatcherQueueController);

    hmodule_ptr_t user32_handle;
    DPI_AWARENESS_CONTEXT (WINAPI *SetThreadDpiAwarenessContext)(DPI_AWARENESS_CONTEXT dpiContext);

    hmodule_ptr_t d3dcompiler_handle;
    HRESULT (WINAPI *D3DCompile)(LPCVOID pSrcData, SIZE_T SrcDataSize, LPCSTR pSourceName, const D3D10_SHADER_MACRO *pDefines, ID3DInclude *pInclude,
                                 LPCSTR pEntrypoint, LPCSTR pTarget, UINT Flags1, UINT Flags2, ID3DBlob **ppCode, ID3DBlob **ppErrorMsgs);
} GfxCaptureFunctions;

// This struct contains all data handled by the capture thread
struct GfxCaptureContextRt {
    ComPtr<IDispatcherQueueController> dispatcher_queue_controller;
    ComPtr<IDispatcherQueue> dispatcher_queue;

    ComPtr<IGraphicsCaptureItem> capture_item;
    ComPtr<IDirect3DDevice> d3d_device;
    ComPtr<IDirect3D11CaptureFramePool> frame_pool;
    ComPtr<IGraphicsCaptureSession> capture_session;

    EventRegistrationToken frame_arrived_token { 0 };
    EventRegistrationToken closed_token { 0 };

    std::mutex frame_arrived_lock;
    std::condition_variable frame_arrived_cond;
    std::atomic<bool> window_closed { false };
    std::atomic<uint64_t> frame_seq { 0 };

    SizeInt32 cap_size { 0, 0 };
    DirectXPixelFormat cap_format { DirectXPixelFormat::DirectXPixelFormat_B8G8R8A8UIntNormalized };
};

struct GfxCaptureContextCpp {
    GfxCaptureFunctions fn;
    std::unique_ptr<GfxCaptureContextRt> rt;

    std::thread rt_thread;
    DWORD rt_thread_id { 0 };
    std::mutex rt_thread_init_lock;
    std::condition_variable rt_thread_init_cond;
    volatile int rt_thread_init_res { INT_MAX };
    std::mutex rt_thread_lock;
    volatile int rt_thread_res { INT_MAX };

    HWND capture_hwnd { nullptr };
    HMONITOR capture_hmonitor { nullptr };

    AVBufferRef *device_ref { nullptr };
    AVHWDeviceContext *device_ctx { nullptr };
    AVD3D11VADeviceContext *device_hwctx { nullptr };

    AVBufferRef *frames_ref { nullptr };
    AVHWFramesContext *frames_ctx { nullptr };
    AVD3D11VAFramesContext *frames_hwctx { nullptr };

    int64_t first_pts { 0 };

    ComPtr<ID3D11VertexShader> vertex_shader;
    ComPtr<ID3D11PixelShader> pixel_shader;
    ComPtr<ID3D11SamplerState> sampler_state;
    ComPtr<ID3D11Buffer> shader_cb;
    ComPtr<ID3D11DeviceContext> deferred_ctx;
};

template <typename T>
static HRESULT get_activation_factory(GfxCaptureContextCpp *ctx, PCWSTR clsid, T** factory) {
    HSTRING_HEADER hsheader = { 0 };
    HSTRING hs = NULL;

    HRESULT hr = ctx->fn.WindowsCreateStringReference(clsid, (UINT32)wcslen(clsid), &hsheader, &hs);
    if (FAILED(hr))
        return hr;

    return ctx->fn.RoGetActivationFactory(hs, IID_PPV_ARGS(factory));
}

#define CHECK_HR(fcall, action) \
    do { \
        HRESULT fhr = fcall; \
        if (FAILED(fhr)) { \
            av_log(avctx, AV_LOG_ERROR, #fcall " failed: 0x%08lX\n", fhr); \
            action; \
        } \
    } while (0)
#define CHECK_HR_RET(...) CHECK_HR((__VA_ARGS__), return AVERROR_EXTERNAL)
#define CHECK_HR_FAIL(...) CHECK_HR((__VA_ARGS__), ret = AVERROR_EXTERNAL; goto fail)
#define CHECK_HR_LOG(...) CHECK_HR((__VA_ARGS__), (void)0)

/**************************************************
 * WinRT Worker Thread                            *
 * All rt_* functions must run only on RT thread! *
 **************************************************/

static void rt_frame_arrived_handler(const std::unique_ptr<GfxCaptureContextRt> &rtctx) {
    rtctx->frame_seq.fetch_add(1, std::memory_order_release);
    rtctx->frame_arrived_cond.notify_one();
}

static void rt_closed_handler(const std::unique_ptr<GfxCaptureContextRt> &rtctx) {
    rtctx->window_closed.store(true, std::memory_order_release);
    rtctx->frame_arrived_cond.notify_one();
}

static void rt_stop_capture_session(AVFilterContext *avctx)
{
    GfxCaptureContext *cctx = CCTX(avctx->priv);
    GfxCaptureContextCpp *ctx = cctx->ctx;
    std::unique_ptr<GfxCaptureContextRt> &rtctx = ctx->rt;

    if (rtctx->closed_token.value && rtctx->capture_item) {
        CHECK_HR_LOG(rtctx->capture_item->remove_Closed(rtctx->closed_token));
        rtctx->closed_token.value = 0;
    }

    if (rtctx->frame_arrived_token.value && rtctx->frame_pool) {
        CHECK_HR_LOG(rtctx->frame_pool->remove_FrameArrived(rtctx->frame_arrived_token));
        rtctx->frame_arrived_token.value = 0;
    }

    if (rtctx->capture_session) {
        ComPtr<IClosable> closable;
        if (SUCCEEDED(rtctx->capture_session.As(&closable))) {
            closable->Close();
        } else {
            av_log(avctx, AV_LOG_ERROR, "Failed to get capture session IClosable interface\n");
        }
    }

    if (rtctx->frame_pool) {
        ComPtr<IDirect3D11CaptureFrame> capture_frame;
        while(SUCCEEDED(rtctx->frame_pool->TryGetNextFrame(&capture_frame)) && capture_frame) {
            capture_frame = nullptr;
        }

        ComPtr<IClosable> closable;
        if (SUCCEEDED(rtctx->frame_pool.As(&closable))) {
            CHECK_HR_LOG(closable->Close());
        } else {
            av_log(avctx, AV_LOG_ERROR, "Failed to get frame pool IClosable interface\n");
        }
    }
}

static int rt_setup_gfxcapture_session(AVFilterContext *avctx)
{
    GfxCaptureContext *cctx = CCTX(avctx->priv);
    GfxCaptureContextCpp *ctx = cctx->ctx;
    std::unique_ptr<GfxCaptureContextRt> &rtctx = ctx->rt;

    ComPtr<IDirect3D11CaptureFramePoolStatics> frame_pool_statics;
    ComPtr<ID3D11Device> d3d11_device = ctx->device_hwctx->device;
    ComPtr<ID3D10Multithread> d3d10_multithread;
    ComPtr<IDXGIDevice> dxgi_device;
    ComPtr<IGraphicsCaptureSession2> session2;
    ComPtr<IGraphicsCaptureSession3> session3;
    ComPtr<IGraphicsCaptureSession5> session5;

    CHECK_HR_RET(d3d11_device.As(&d3d10_multithread));
    d3d10_multithread->SetMultithreadProtected(TRUE);

    rtctx->cap_size.Width = rtctx->cap_size.Height = 0;
    CHECK_HR_RET(rtctx->capture_item->get_Size(&rtctx->cap_size));

    CHECK_HR_RET(get_activation_factory<IDirect3D11CaptureFramePoolStatics>(ctx, RuntimeClass_Windows_Graphics_Capture_Direct3D11CaptureFramePool, &frame_pool_statics));

    CHECK_HR_RET(d3d11_device.As(&dxgi_device));
    CHECK_HR_RET(ctx->fn.CreateDirect3D11DeviceFromDXGIDevice(dxgi_device.Get(), &rtctx->d3d_device));
    CHECK_HR_RET(frame_pool_statics->Create(rtctx->d3d_device.Get(), rtctx->cap_format, CAPTURE_POOL_SIZE, rtctx->cap_size, &rtctx->frame_pool));
    CHECK_HR_RET(rtctx->frame_pool->CreateCaptureSession(rtctx->capture_item.Get(), &rtctx->capture_session));

    if (SUCCEEDED(rtctx->capture_session.As(&session2))) {
        if (FAILED(session2->put_IsCursorCaptureEnabled(cctx->capture_cursor))) {
            av_log(avctx, AV_LOG_WARNING, "Failed setting cursor capture mode\n");
        }
    } else {
        av_log(avctx, AV_LOG_WARNING, "Cursor capture unavailable\n");
    }

    if (SUCCEEDED(rtctx->capture_session.As(&session3))) {
        // this one is weird, it can return failure but still work
        if (FAILED(session3->put_IsBorderRequired(cctx->display_border))) {
            av_log(avctx, AV_LOG_WARNING, "Failed setting border drawing mode\n");
        }
    } else {
        av_log(avctx, AV_LOG_WARNING, "Disabling border drawing unavailable\n");
    }

    if (SUCCEEDED(rtctx->capture_session.As(&session5))) {
        TimeSpan ivl = { av_rescale_q(1, av_inv_q(cctx->frame_rate), (AVRational){1, TIMESPAN_RES}) };
        if (FAILED(session5->put_MinUpdateInterval(ivl))) {
            av_log(avctx, AV_LOG_WARNING, "Failed setting minimum update interval, framerate may be limited\n");
        }
    } else {
        av_log(avctx, AV_LOG_WARNING, "Setting minimum update interval unavailable, framerate may be limited\n");
    }

    rtctx->window_closed = 0;

    CHECK_HR_RET(rtctx->capture_item->add_Closed(
        create_cb_handler<ITypedEventHandler<GraphicsCaptureItem*,IInspectable*>, IGraphicsCaptureItem*, IInspectable*>(
            [avctx, ctx](auto, auto) {
                av_log(avctx, AV_LOG_INFO, "Capture item closed\n");
                rt_closed_handler(ctx->rt);
                return S_OK;
            }).Get(), &rtctx->closed_token));

    CHECK_HR_RET(rtctx->frame_pool->add_FrameArrived(
        create_cb_handler<ITypedEventHandler<Direct3D11CaptureFramePool*,IInspectable*>, IDirect3D11CaptureFramePool*, IInspectable*>(
            [avctx, ctx](auto, auto) {
                av_log(avctx, AV_LOG_TRACE, "Frame arrived\n");
                rt_frame_arrived_handler(ctx->rt);
                return S_OK;
            }).Get(), &rtctx->frame_arrived_token));

    return 0;
}

static int rt_setup_gfxcapture_capture(AVFilterContext *avctx)
{
    GfxCaptureContext *cctx = CCTX(avctx->priv);
    GfxCaptureContextCpp *ctx = cctx->ctx;
    std::unique_ptr<GfxCaptureContextRt> &rtctx = ctx->rt;
    int ret = 0;

    ComPtr<IGraphicsCaptureItemInterop> capture_item_interop;
    CHECK_HR_RET(get_activation_factory<IGraphicsCaptureItemInterop>(ctx, RuntimeClass_Windows_Graphics_Capture_GraphicsCaptureItem, &capture_item_interop));

    if (ctx->capture_hmonitor) {
        HRESULT hr = capture_item_interop->CreateForMonitor(ctx->capture_hmonitor, IID_PPV_ARGS(&rtctx->capture_item));
        if (FAILED(hr)) {
            av_log(avctx, AV_LOG_ERROR, "Failed to setup graphics capture for monitor\n");
            return AVERROR_EXTERNAL;
        }
    } else if (ctx->capture_hwnd) {
        HRESULT hr = capture_item_interop->CreateForWindow(ctx->capture_hwnd, IID_PPV_ARGS(&rtctx->capture_item));
        if (FAILED(hr)) {
            av_log(avctx, AV_LOG_ERROR, "Failed to setup graphics capture for window\n");
            return AVERROR_EXTERNAL;
        }
    }

    ret = rt_setup_gfxcapture_session(avctx);
    if (ret < 0) {
        av_log(avctx, AV_LOG_ERROR, "Failed to setup graphics capture pool\n");
        return ret;
    }

    if (FAILED(ctx->rt->capture_session->StartCapture())) {
        av_log(avctx, AV_LOG_ERROR, "Failed to start graphics capture session\n");
        ret = AVERROR_EXTERNAL;
        return ret;
    }

    return 0;
}

static int rt_try_get_next_frame(AVFilterContext *avctx, ComPtr<IDirect3D11CaptureFrame> *capture_frame)
{
    GfxCaptureContext *cctx = CCTX(avctx->priv);
    GfxCaptureContextCpp *ctx = cctx->ctx;
    std::unique_ptr<GfxCaptureContextRt> &rtctx = ctx->rt;

    ComPtr<IDirect3DSurface> capture_surface;
    ComPtr<IDirect3DDxgiInterfaceAccess> dxgi_interface_access;
    ComPtr<ID3D11Texture2D> frame_texture;
    SizeInt32 frame_size = { 0, 0 };

    CHECK_HR_RET(rtctx->frame_pool->TryGetNextFrame(capture_frame->ReleaseAndGetAddressOf()));
    if (!capture_frame->Get())
        return AVERROR(EAGAIN);

    CHECK_HR_RET(capture_frame->Get()->get_ContentSize(&frame_size));
    if (frame_size.Width != rtctx->cap_size.Width || frame_size.Height != rtctx->cap_size.Height) {
        av_log(avctx, AV_LOG_VERBOSE, "Capture size changed to %dx%d\n", frame_size.Width, frame_size.Height);

        CHECK_HR_RET(rtctx->frame_pool->Recreate(rtctx->d3d_device.Get(), rtctx->cap_format, CAPTURE_POOL_SIZE, frame_size));
        rtctx->cap_size = frame_size;
    }

    return 0;
}

static int rt_setup_winrt(AVFilterContext *avctx)
{
    GfxCaptureContext *cctx = CCTX(avctx->priv);
    GfxCaptureContextCpp *ctx = cctx->ctx;
    std::unique_ptr<GfxCaptureContextRt> &rtctx = ctx->rt;
    MSG msg;

    // pre-create the message-queue
    PeekMessage(&msg, nullptr, 0, 0, PM_NOREMOVE);

    DispatcherQueueOptions options {
        .dwSize = sizeof(DispatcherQueueOptions),
        .threadType = DISPATCHERQUEUE_THREAD_TYPE::DQTYPE_THREAD_CURRENT,
        .apartmentType = DISPATCHERQUEUE_THREAD_APARTMENTTYPE::DQTAT_COM_NONE
    };
    CHECK_HR_RET(ctx->fn.CreateDispatcherQueueController(options, &rtctx->dispatcher_queue_controller));
    CHECK_HR_RET(rtctx->dispatcher_queue_controller->get_DispatcherQueue(&rtctx->dispatcher_queue));

    return 0;
}

static void rt_thread_uninit(AVFilterContext *avctx)
{
    GfxCaptureContext *cctx = CCTX(avctx->priv);
    GfxCaptureContextCpp *ctx = cctx->ctx;

    rt_stop_capture_session(avctx);

    ctx->rt.reset();
    ctx->fn.RoUninitialize();
}

static int rt_thread_init(AVFilterContext *avctx)
{
    GfxCaptureContext *cctx = CCTX(avctx->priv);
    GfxCaptureContextCpp *ctx = cctx->ctx;
    HRESULT hr;
    int ret;

    ctx->rt = std::make_unique<GfxCaptureContextRt>();
    if (!ctx->rt)
        return AVERROR(ENOMEM);

    ctx->fn.SetThreadDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);

    hr = ctx->fn.RoInitialize(RO_INIT_MULTITHREADED);
    if (FAILED(hr)) {
        av_log(avctx, AV_LOG_ERROR, "Failed to initialize WinRT\n");
        ctx->rt.reset();
        return AVERROR_EXTERNAL;
    }

    ret = rt_setup_winrt(avctx);
    if (ret < 0) {
        av_log(avctx, AV_LOG_ERROR, "Failed to setup WinRT\n");
        goto fail;
    }

    ret = rt_setup_gfxcapture_capture(avctx);
    if (ret < 0) {
        av_log(avctx, AV_LOG_ERROR, "Failed to setup graphics capture\n");
        goto fail;
    }

    return 0;

fail:
    rt_thread_uninit(avctx);
    return ret;
}

static int rt_thread_worker(AVFilterContext *avctx)
{
    GfxCaptureContext *cctx = CCTX(avctx->priv);
    GfxCaptureContextCpp *ctx = cctx->ctx;
    std::unique_ptr<GfxCaptureContextRt> &rtctx = ctx->rt;
    ComPtr<IAsyncAction> async;
    MSG msg;

    av_log(avctx, AV_LOG_DEBUG, "Starting message loop\n");

    while (BOOL res = GetMessage(&msg, NULL, 0, 0)) {
        if (res == -1) {
            av_log(avctx, AV_LOG_ERROR, "Failed to get message\n");
            return AVERROR(EIO);
        }

        if (!msg.hwnd && msg.message == WM_RT_THREAD_SHUTDOWN) {
            av_log(avctx, AV_LOG_DEBUG, "Initializing RT thread shutdown\n");
            if (FAILED(rtctx->dispatcher_queue_controller->ShutdownQueueAsync(&async))) {
                av_log(avctx, AV_LOG_ERROR, "Failed to shutdown dispatcher queue\n");
                return AVERROR_EXTERNAL;
            }
            async->put_Completed(create_cb_handler<IAsyncActionCompletedHandler, IAsyncAction*, AsyncStatus>(
                [avctx, ctx](auto, auto status) {
                    PostThreadMessage(ctx->rt_thread_id, WM_QUIT, 0, 0);
                    av_log(avctx, AV_LOG_DEBUG, "RT thread async shutdown completed: %d\n", (int)status);
                    return S_OK;
                }).Get());
            continue;
        }

        av_log(avctx, AV_LOG_TRACE, "Got message: %u\n", msg.message);

        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    if (!async) {
        av_log(avctx, AV_LOG_ERROR, "RT Thread message loop ended without proper shutdown\n");
        return AVERROR_EXTERNAL;
    }

    av_log(avctx, AV_LOG_DEBUG, "Message loop ended\n");

    return msg.wParam;
}

static void rt_thread_entry(AVFilterContext *avctx)
{
    GfxCaptureContext *cctx = CCTX(avctx->priv);
    GfxCaptureContextCpp *ctx = cctx->ctx;

    std::lock_guard rt_lock(ctx->rt_thread_lock);

    {
        std::lock_guard init_lock(ctx->rt_thread_init_lock);
        ctx->rt_thread_id = GetCurrentThreadId();
        ctx->rt_thread_init_res = rt_thread_init(avctx);
        ctx->rt_thread_init_cond.notify_all();
        if (ctx->rt_thread_init_res < 0)
            return;
    }

    ctx->rt_thread_res = rt_thread_worker(avctx);

    std::lock_guard uninit_lock(ctx->rt_thread_init_lock);
    rt_thread_uninit(avctx);
}

/**********************************
 * RT Thread Management Functions *
 **********************************/

static void stop_rt_thread(AVFilterContext *avctx)
{
    GfxCaptureContext *cctx = CCTX(avctx->priv);
    GfxCaptureContextCpp *ctx = cctx->ctx;

    if (ctx->rt_thread.joinable()) {
        if (!PostThreadMessage(ctx->rt_thread_id, WM_RT_THREAD_SHUTDOWN, 0, 0)) {
            av_log(avctx, AV_LOG_ERROR, "Failed to post shutdown message to RT thread\n");
            return;
        }
        ctx->rt_thread.join();
    }
}

static int start_rt_thread(AVFilterContext *avctx)
{
    GfxCaptureContext *cctx = CCTX(avctx->priv);
    GfxCaptureContextCpp *ctx = cctx->ctx;

    std::unique_lock rt_lock(ctx->rt_thread_init_lock);
    ctx->rt_thread_init_res = INT_MAX;

    ctx->rt_thread = std::thread(rt_thread_entry, avctx);
    if (!ctx->rt_thread.joinable())
        return AVERROR(ENOMEM);

    if (!ctx->rt_thread_init_cond.wait_for(rt_lock, std::chrono::seconds(1), [&]() {
        return ctx->rt_thread_init_res != INT_MAX;
    })) {
        av_log(avctx, AV_LOG_ERROR, "RT thread init timed out\n");
        return AVERROR(ETIMEDOUT);
    }

    return ctx->rt_thread_init_res;
}

static int run_on_rt_thread(AVFilterContext *avctx, const std::function<int()> &cb)
{
    GfxCaptureContext *cctx = CCTX(avctx->priv);
    GfxCaptureContextCpp *ctx = cctx->ctx;
    std::unique_ptr<GfxCaptureContextRt> &rtctx = ctx->rt;

    std::lock_guard rt_lock(ctx->rt_thread_init_lock);

    if (!rtctx) {
        av_log(avctx, AV_LOG_ERROR, "RT thread not initialized\n");
        return AVERROR(ENOSYS);
    }

    struct CBData {
        std::mutex mutex;
        std::condition_variable cond;
        std::atomic<bool> done { false };
        std::atomic<bool> cancel { false };
        int ret = AVERROR_BUG;
    };
    auto cbdata = std::make_shared<CBData>();

    std::unique_lock cblock(cbdata->mutex);

    boolean res = 0;
    CHECK_HR_RET(rtctx->dispatcher_queue->TryEnqueue(
        create_cb_handler<IDispatcherQueueHandler>(
            [cb = std::move(cb), cbdata]() {
                {
                    std::lock_guard lock(cbdata->mutex);
                    if (cbdata->cancel.load(std::memory_order_acquire))
                        return S_OK;
                    cbdata->ret = cb();
                    cbdata->done.store(true, std::memory_order_release);
                }

                cbdata->cond.notify_one();
                return S_OK;
            }).Get(), &res));
    if (!res) {
        av_log(avctx, AV_LOG_ERROR, "Failed to enqueue RT thread callback\n");
        return AVERROR_EXTERNAL;
    }

    if (!cbdata->cond.wait_for(cblock, std::chrono::seconds(1), [&]() { return cbdata->done.load(std::memory_order_acquire); })) {
        cbdata->cancel.store(true, std::memory_order_release);
        av_log(avctx, AV_LOG_ERROR, "RT thread callback timed out\n");
        return AVERROR(ETIMEDOUT);
    }

    return cbdata->ret;
}

/*******************************
 * Standard AVFilter functions *
 *******************************/

static int find_capture_source(AVFilterContext *avctx)
{
    GfxCaptureContext *cctx = CCTX(avctx->priv);
    GfxCaptureContextCpp *ctx = cctx->ctx;
    int cur_idx = 0;

    ctx->capture_hwnd = NULL;
    ctx->capture_hmonitor = NULL;

    if (cctx->user_hmonitor) {
        ctx->capture_hmonitor = (HMONITOR)(uintptr_t)cctx->user_hmonitor;
        return 0;
    } else if (cctx->user_hwnd) {
        ctx->capture_hwnd = (HWND)(uintptr_t)cctx->user_hwnd;
        return 0;
    } else if (cctx->monitor_idx >= 0) {
        auto [state, cb] = make_win32_callback([&](HMONITOR hmonitor, HDC, LPRECT) {
            if (cur_idx++ == cctx->monitor_idx) {
                av_log(avctx, AV_LOG_DEBUG, "Found capture monitor: %d\n", cctx->monitor_idx);
                ctx->capture_hmonitor = hmonitor;
                return FALSE;
            }
            return TRUE;
        });
        if (EnumDisplayMonitors(NULL, NULL, cb.first, cb.second) || !ctx->capture_hmonitor)
            return AVERROR(ENOENT);
        return 0;
    } else if (cctx->window_name && cctx->window_name[0]) {
        std::string window_text;
        auto [state, cb] = make_win32_callback([&](HWND hwnd) {
            window_text.resize(GetWindowTextLengthA(hwnd) + 1);
            int len = GetWindowTextA(hwnd, window_text.data(), window_text.size());
            if (len <= 0)
                return TRUE;
            window_text.resize(len);

            // TODO: more sophisticated matching
            if (window_text.find(cctx->window_name) != std::string::npos) {
                av_log(avctx, AV_LOG_DEBUG, "Found capture window: %s\n", window_text.c_str());
                ctx->capture_hwnd = hwnd;
                return FALSE;
            }

            return TRUE;
        });
        if (EnumWindows(cb.first, cb.second) || !ctx->capture_hwnd)
            return AVERROR(ENOENT);
        return 0;
    }

    av_log(avctx, AV_LOG_ERROR, "No capture source specified\n");
    return AVERROR(EINVAL);
}

av_cold void ff_gfxcapture_uninit(AVFilterContext *avctx)
{
    GfxCaptureContext *cctx = CCTX(avctx->priv);
    GfxCaptureContextCpp *ctx = cctx->ctx;

    if (!ctx)
        return;

    stop_rt_thread(avctx);

    ctx->vertex_shader = nullptr;
    ctx->pixel_shader = nullptr;
    ctx->sampler_state = nullptr;
    ctx->deferred_ctx = nullptr;
    ctx->shader_cb = nullptr;

    av_buffer_unref(&ctx->frames_ref);
    av_buffer_unref(&ctx->device_ref);

    delete ctx;
}

template<typename T>
static av_cold void GetProcAddressTyped(const hmodule_ptr_t &hModule, LPCSTR lpProcName, T *out) {
    *out = reinterpret_cast<T>(GetProcAddress(hModule.get(), lpProcName));
}

static av_cold int load_functions(AVFilterContext *avctx)
{
    GfxCaptureContext *cctx = CCTX(avctx->priv);
    GfxCaptureContextCpp *ctx = cctx->ctx;

#define LOAD_DLL(handle, name) \
    handle = std::move(hmodule_ptr_t(LoadLibraryExA(name, NULL, LOAD_LIBRARY_SEARCH_SYSTEM32))); \
    if (!handle) { \
        av_log(avctx, AV_LOG_ERROR, "Failed opening " #name "\n"); \
        return AVERROR(ENOSYS); \
    }

#define LOAD_FUNC(handle, name) \
    GetProcAddressTyped(handle, #name, &ctx->fn.name); \
    if (!ctx->fn.name) { \
        av_log(avctx, AV_LOG_ERROR, "Failed loading " #name "\n"); \
        return AVERROR(ENOSYS); \
    }

    // this handle is not used anywhere, but letting it get auto-freed during RoUninit causes crashes
    LOAD_DLL(ctx->fn.graphicscapture_handle, "graphicscapture.dll");

    LOAD_DLL(ctx->fn.combase_handle, "combase.dll");
    LOAD_DLL(ctx->fn.dwmapi_handle, "dwmapi.dll");
    LOAD_DLL(ctx->fn.d3d11_handle, "d3d11.dll");
    LOAD_DLL(ctx->fn.coremsg_handle, "coremessaging.dll");
    LOAD_DLL(ctx->fn.user32_handle, "user32.dll");
    LOAD_DLL(ctx->fn.d3dcompiler_handle, "d3dcompiler_47.dll");

    LOAD_FUNC(ctx->fn.combase_handle, RoInitialize);
    LOAD_FUNC(ctx->fn.combase_handle, RoUninitialize);
    LOAD_FUNC(ctx->fn.combase_handle, RoGetActivationFactory);
    LOAD_FUNC(ctx->fn.combase_handle, WindowsCreateStringReference);

    LOAD_FUNC(ctx->fn.dwmapi_handle, DwmGetWindowAttribute);

    LOAD_FUNC(ctx->fn.d3d11_handle, CreateDirect3D11DeviceFromDXGIDevice);

    LOAD_FUNC(ctx->fn.coremsg_handle, CreateDispatcherQueueController);

    LOAD_FUNC(ctx->fn.user32_handle, SetThreadDpiAwarenessContext);

    LOAD_FUNC(ctx->fn.d3dcompiler_handle, D3DCompile);

#undef LOAD_FUNC
#undef LOAD_DLL
    return 0;
}

av_cold int ff_gfxcapture_init(AVFilterContext *avctx)
{
    GfxCaptureContext *cctx = CCTX(avctx->priv);
    int ret = 0;

    GfxCaptureContextCpp *ctx = cctx->ctx = new GfxCaptureContextCpp();
    if (!ctx)
        return AVERROR(ENOMEM);

    ret = load_functions(avctx);
    if (ret < 0) {
        ctx->fn.RoUninitialize = nullptr;
        goto fail;
    }

    return 0;

fail:
    ff_gfxcapture_uninit(avctx);
    return ret;
}

static int init_hwframes_ctx(AVFilterContext *avctx)
{
    GfxCaptureContext *cctx = CCTX(avctx->priv);
    GfxCaptureContextCpp *ctx = cctx->ctx;
    int ret = 0;

    ctx->frames_ref = av_hwframe_ctx_alloc(ctx->device_ref);
    if (!ctx->frames_ref)
        return AVERROR(ENOMEM);
    ctx->frames_ctx = (AVHWFramesContext*)ctx->frames_ref->data;
    ctx->frames_hwctx = (AVD3D11VAFramesContext*)ctx->frames_ctx->hwctx;

    ctx->frames_ctx->format    = AV_PIX_FMT_D3D11;
    ctx->frames_ctx->width     = ctx->rt->cap_size.Width;
    ctx->frames_ctx->height    = ctx->rt->cap_size.Height;
    ctx->frames_ctx->sw_format = AV_PIX_FMT_BGRA; //TODO: more?

    ctx->frames_hwctx->BindFlags = D3D11_BIND_RENDER_TARGET;

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

static int setup_gfxcapture_capture(AVFilterContext *avctx)
{
    int ret = 0;

    stop_rt_thread(avctx);

    ret = find_capture_source(avctx);
    if (ret < 0) {
        av_log(avctx, AV_LOG_ERROR, "Failed to find capture source\n");
        return ret;
    }

    ret = start_rt_thread(avctx);
    if (ret < 0) {
        av_log(avctx, AV_LOG_ERROR, "Failed to start graphics capture thread\n");
        return ret;
    }

    return 0;
}

static const char render_shader_src[] = HLSL(
    struct VSOut {
        float4 pos : SV_Position;
        float2 uv : TEXCOORD0;
    };

    VSOut main_vs(uint id : SV_VertexID) {
        float2 p = float2(id == 2 ? 3.0 : -1.0, id == 1 ? 3.0 : -1.0);
        VSOut o;
        o.pos = float4(p, 0, 1);
        o.uv = float2((p.x + 1) * 0.5, 1 - (p.y + 1) * 0.5);
        return o;
    }

    Texture2D t0 : register(t0);
    SamplerState s0 : register(s0);

    cbuffer cb : register(b0) {
        float2 tS;
        float2 dS;
    };

    float4 cubic(float v) {
        float4 n = float4(1.0, 2.0, 3.0, 4.0) - v;
        float4 s = n * n * n;
        float  x = s.x;
        float  y = s.y - 4.0 * s.x;
        float  z = s.z - 4.0 * s.y + 6.0 * s.x;
        float  w = 6.0 - x - y - z;
        return float4(x, y, z, w) * (1.0 / 6.0);
    }

    float4 texBicubic(Texture2D t, SamplerState ss, float2 uv) {
        float2 itS = 1.0 / tS;

        float2 tc = uv * tS - 0.5;
        float2 fxy = frac(tc);
        tc -= fxy;

        float4 xc = cubic(fxy.x);
        float4 yc = cubic(fxy.y);

        float4 s = float4(xc.xz + xc.yw, yc.xz + yc.yw);
        float4 o = tc.xxyy + (float2(-0.5, 1.5)).xyxy + float4(xc.yw, yc.yw) / s;
        o *= itS.xxyy;

        float4 s0 = t.Sample(ss, o.xz);
        float4 s1 = t.Sample(ss, o.yz);
        float4 s2 = t.Sample(ss, o.xw);
        float4 s3 = t.Sample(ss, o.yw);

        float sx = s.x / (s.x + s.y);
        float sy = s.z / (s.z + s.w);

        return lerp(lerp(s3, s2, sx), lerp(s1, s0, sx), sy);
    }

    float4 main_ps(VSOut i) : SV_Target {
        return t0.Sample(s0, i.uv);
    }

    float4 main_ps_bicubic(VSOut i) : SV_Target {
        if (all(tS == dS))
            return main_ps(i);
        return texBicubic(t0, s0, i.uv);
    }
);

static int prepare_render_resources(AVFilterContext *avctx)
{
    GfxCaptureContext *cctx = CCTX(avctx->priv);
    GfxCaptureContextCpp *ctx = cctx->ctx;
    HRESULT hr;

    ComPtr<ID3DBlob> vs_blob, ps_blob, err_blob;
    CD3D11_SAMPLER_DESC sampler_desc(CD3D11_DEFAULT{});
    UINT flags = D3DCOMPILE_OPTIMIZATION_LEVEL3;

    hr = ctx->fn.D3DCompile(render_shader_src, sizeof(render_shader_src) - 1, NULL, NULL, NULL, "main_vs", "vs_4_0", flags, 0, &vs_blob, &err_blob);
    if (FAILED(hr)) {
        if (err_blob) {
            av_log(avctx, AV_LOG_ERROR, "Failed compiling vertex shader: %.*s\n", (int)err_blob->GetBufferSize(), (char*)err_blob->GetBufferPointer());
        } else {
            av_log(avctx, AV_LOG_ERROR, "Failed compiling vertex shader: 0x%08lX\n", hr);
        }
        return AVERROR_EXTERNAL;
    }

    const char *ps_entry = "main_ps_bicubic";
    if (cctx->resize_mode == GFX_RESIZE_CROP || cctx->scale_mode == GFX_SCALE_POINT) {
        ps_entry = "main_ps";
        sampler_desc.Filter = D3D11_FILTER_MIN_MAG_MIP_POINT;
    }

    hr = ctx->fn.D3DCompile(render_shader_src, sizeof(render_shader_src) - 1, NULL, NULL, NULL, ps_entry, "ps_4_0", flags, 0, &ps_blob, &err_blob);
    if (FAILED(hr)) {
        if (err_blob) {
            av_log(avctx, AV_LOG_ERROR, "Failed compiling pixel shader: %.*s\n", (int)err_blob->GetBufferSize(), (char*)err_blob->GetBufferPointer());
        } else {
            av_log(avctx, AV_LOG_ERROR, "Failed compiling pixel shader: 0x%08lX\n", hr);
        }
        return AVERROR_EXTERNAL;
    }

    CHECK_HR_RET(ctx->device_hwctx->device->CreateVertexShader(vs_blob->GetBufferPointer(), vs_blob->GetBufferSize(), NULL, &ctx->vertex_shader));
    CHECK_HR_RET(ctx->device_hwctx->device->CreatePixelShader(ps_blob->GetBufferPointer(), ps_blob->GetBufferSize(), NULL, &ctx->pixel_shader));

    CHECK_HR_RET(ctx->device_hwctx->device->CreateSamplerState(&sampler_desc, &ctx->sampler_state));

    D3D11_BUFFER_DESC cb_desc = {
        .ByteWidth = 16,
        .Usage = D3D11_USAGE_DYNAMIC,
        .BindFlags = D3D11_BIND_CONSTANT_BUFFER,
        .CPUAccessFlags = D3D11_CPU_ACCESS_WRITE
    };
    CHECK_HR_RET(ctx->device_hwctx->device->CreateBuffer(&cb_desc, NULL, &ctx->shader_cb));

    CHECK_HR_RET(ctx->device_hwctx->device->CreateDeferredContext(0, &ctx->deferred_ctx));

    return 0;
}

int ff_gfxcapture_config_props(AVFilterLink *outlink)
{
    AVFilterContext *avctx = outlink->src;
    GfxCaptureContext *cctx = CCTX(avctx->priv);
    GfxCaptureContextCpp *ctx = cctx->ctx;

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

    ret = prepare_render_resources(avctx);
    if (ret < 0) {
        av_log(avctx, AV_LOG_ERROR, "Failed to prepare render resources\n");
        return ret;
    }

    ret = setup_gfxcapture_capture(avctx);
    if (ret < 0) {
        av_log(avctx, AV_LOG_ERROR, "Failed to setup graphics capture\n");
        return ret;
    }

    ret = init_hwframes_ctx(avctx);
    if (ret < 0)
        return ret;

    link->hw_frames_ctx = av_buffer_ref(ctx->frames_ref);
    if (!link->hw_frames_ctx)
        return AVERROR(ENOMEM);

    outlink->w = ctx->rt->cap_size.Width;
    outlink->h = ctx->rt->cap_size.Height;
    outlink->time_base = (AVRational){1, TIMESPAN_RES};
    link->frame_rate = cctx->frame_rate;

    av_log(avctx, AV_LOG_DEBUG, "Capture setup with res %dx%d\n", outlink->w, outlink->h);

    return 0;
}

static int render_capture_to_frame(AVFilterContext *avctx, AVFrame *frame, const ComPtr<ID3D11Texture2D> &src_tex)
{
    GfxCaptureContext *cctx = CCTX(avctx->priv);
    GfxCaptureContextCpp *ctx = cctx->ctx;
    ID3D11Device *dev = ctx->device_hwctx->device;
    ID3D11DeviceContext *dev_ctx = ctx->device_hwctx->device_context;
    ID3D11DeviceContext *def_ctx = ctx->deferred_ctx.Get();

    D3D11_TEXTURE2D_DESC dst_tex_desc;
    reinterpret_cast<ID3D11Texture2D*>(frame->data[0])->GetDesc(&dst_tex_desc);
    if (dst_tex_desc.ArraySize != 1) {
        av_log(avctx, AV_LOG_ERROR, "Rendering to array texture not implemented\n");
        return AVERROR(EINVAL);
    }

    D3D11_TEXTURE2D_DESC src_tex_desc;
    src_tex->GetDesc(&src_tex_desc);

    D3D11_RENDER_TARGET_VIEW_DESC target_desc = {
        .Format = dst_tex_desc.Format,
        .ViewDimension = D3D11_RTV_DIMENSION_TEXTURE2D,
        .Texture2D = { .MipSlice = 0 }
    };

    ComPtr<ID3D11RenderTargetView> rtv;
    CHECK_HR_RET(dev->CreateRenderTargetView(
        reinterpret_cast<ID3D11Resource*>(frame->data[0]), &target_desc, &rtv));

    ComPtr<ID3D11ShaderResourceView> srv;
    CHECK_HR_RET(dev->CreateShaderResourceView(src_tex.Get(), nullptr, &srv));

    D3D11_MAPPED_SUBRESOURCE map;
    CHECK_HR_RET(def_ctx->Map(ctx->shader_cb.Get(), 0, D3D11_MAP_WRITE_DISCARD, 0, &map));
    float *cb_data = static_cast<float*>(map.pData);
    cb_data[0] = (float)src_tex_desc.Width;
    cb_data[1] = (float)src_tex_desc.Height;
    cb_data[2] = (float)dst_tex_desc.Width;
    cb_data[3] = (float)dst_tex_desc.Height;
    def_ctx->Unmap(ctx->shader_cb.Get(), 0);

    def_ctx->OMSetRenderTargets(1, rtv.GetAddressOf(), nullptr);
    def_ctx->ClearRenderTargetView(rtv.Get(), (const float[4]){0.f, 0.f, 0.f, 1.f});

    D3D11_VIEWPORT viewport = {
        .MinDepth = 0.f,
        .MaxDepth = 1.f
    };

    switch (cctx->resize_mode) {
    case GFX_RESIZE_CROP:
        viewport.Width  = src_tex_desc.Width;
        viewport.Height = src_tex_desc.Height;
        break;
    case GFX_RESIZE_SCALE:
        viewport.Width  = dst_tex_desc.Width;
        viewport.Height = dst_tex_desc.Height;
        break;
    case GFX_RESIZE_SCALE_ASPECT: {
        float scale = FFMIN(dst_tex_desc.Width / (float)src_tex_desc.Width,
                            dst_tex_desc.Height / (float)src_tex_desc.Height);
        viewport.Width  = src_tex_desc.Width * scale;
        viewport.Height = src_tex_desc.Height * scale;
        break;
    }
    default:
        av_log(avctx, AV_LOG_ERROR, "Invalid scaling mode\n");
        return AVERROR_BUG;
    };

    def_ctx->RSSetViewports(1, &viewport);

    def_ctx->IASetPrimitiveTopology(D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
    def_ctx->VSSetShader(ctx->vertex_shader.Get(), nullptr, 0);
    def_ctx->PSSetShader(ctx->pixel_shader.Get(), nullptr, 0);
    def_ctx->PSSetSamplers(0, 1, ctx->sampler_state.GetAddressOf());
    def_ctx->PSSetShaderResources(0, 1, srv.GetAddressOf());
    def_ctx->PSSetConstantBuffers(0, 1, ctx->shader_cb.GetAddressOf());

    def_ctx->Draw(3, 0);

    ComPtr<ID3D11CommandList> cmd_list;
    CHECK_HR_RET(def_ctx->FinishCommandList(FALSE, &cmd_list));
    dev_ctx->ExecuteCommandList(cmd_list.Get(), FALSE);

    return 0;
}

static int process_frame_if_exists(AVFilterLink *outlink)
{
    AVFilterContext *avctx = outlink->src;
    GfxCaptureContext *cctx = CCTX(avctx->priv);
    GfxCaptureContextCpp *ctx = cctx->ctx;
    std::unique_ptr<GfxCaptureContextRt> &rtctx = ctx->rt;
    int ret;

    AVFrame *frame = nullptr;

    ret = run_on_rt_thread(avctx, [&]() {
        ComPtr<IDirect3D11CaptureFrame> capture_frame;
        ComPtr<IDirect3DSurface> capture_surface;
        ComPtr<IDirect3DDxgiInterfaceAccess> dxgi_interface_access;
        ComPtr<ID3D11Texture2D> frame_texture;
        SizeInt32 frame_size = { 0, 0 };
        TimeSpan frame_time = { 0 };

        ret = rt_try_get_next_frame(avctx, &capture_frame);
        if (ret < 0)
            return ret;

        CHECK_HR_RET(capture_frame->get_ContentSize(&frame_size));
        CHECK_HR_RET(capture_frame->get_SystemRelativeTime(&frame_time));

        CHECK_HR_RET(capture_frame->get_Surface(&capture_surface));
        CHECK_HR_RET(capture_surface.As(&dxgi_interface_access));
        CHECK_HR_RET(dxgi_interface_access->GetInterface(IID_PPV_ARGS(&frame_texture)));

        if (!frame_texture)
            return AVERROR(EAGAIN);

        frame = ff_get_video_buffer(outlink, rtctx->cap_size.Width, rtctx->cap_size.Height);
        if (!frame)
            return AVERROR(ENOMEM);

        frame->pts = frame_time.Duration;

        return render_capture_to_frame(avctx, frame, frame_texture);
    });
    if (ret < 0)
        return ret;

    frame->sample_aspect_ratio = (AVRational){1, 1};

    frame->color_range     = AVCOL_RANGE_JPEG;
    frame->color_primaries = AVCOL_PRI_BT709;
    frame->color_trc       = AVCOL_TRC_IEC61966_2_1;
    frame->colorspace      = AVCOL_SPC_RGB;

    if (!ctx->first_pts)
        ctx->first_pts = frame->pts;
    frame->pts -= ctx->first_pts;

    return ff_filter_frame(outlink, frame);
}

int ff_gfxcapture_request_frame(AVFilterLink *outlink)
{
    AVFilterContext *avctx = outlink->src;
    GfxCaptureContext *cctx = CCTX(avctx->priv);
    GfxCaptureContextCpp *ctx = cctx->ctx;
    std::unique_ptr<GfxCaptureContextRt> &rtctx = ctx->rt;

    std::lock_guard rtlock(ctx->rt_thread_init_lock);
    if (!rtctx) {
        av_log(avctx, AV_LOG_ERROR, "RT thread not initialized\n");
        return AVERROR(ENOSYS);
    }

    std::unique_lock frame_lock(rtctx->frame_arrived_lock);

    for (;;) {
        uint64_t last_seq = rtctx->frame_seq.load(std::memory_order_acquire);

        int ret = process_frame_if_exists(outlink);
        if (ret != AVERROR(EAGAIN))
            return ret;

        if (rtctx->window_closed.load(std::memory_order_acquire))
            return AVERROR_EOF;

        if (!rtctx->frame_arrived_cond.wait_for(frame_lock, std::chrono::seconds(1), [&]() {
            return rtctx->frame_seq.load(std::memory_order_acquire) != last_seq ||
                   rtctx->window_closed.load(std::memory_order_acquire);
        }))
            return AVERROR(EAGAIN);
    }
}
