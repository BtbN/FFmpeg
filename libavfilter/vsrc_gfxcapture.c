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

#include "libavutil/internal.h"
#include "libavutil/opt.h"
#include "avfilter.h"
#include "filters.h"

#include "vsrc_gfxcapture.h"

#define OFFSET(x) offsetof(GfxCaptureContext, x)
#define FLAGS AV_OPT_FLAG_VIDEO_PARAM|AV_OPT_FLAG_FILTERING_PARAM
static const AVOption gfxcapture_options[] = {
    { "window_name",     "name of the window to capture",   OFFSET(window_name),    AV_OPT_TYPE_STRING,     { .str = NULL },   0, INT_MAX,    FLAGS },
    { "monitor_idx",     "index of the monitor to capture", OFFSET(monitor_idx),    AV_OPT_TYPE_INT,        { .i64 = -1 },    -1, INT_MAX,    FLAGS },
    { "capture_cursor",  "capture mouse cursor",            OFFSET(capture_cursor), AV_OPT_TYPE_BOOL,       { .i64 = 1 },      0, 1,          FLAGS },
    { "display_border",  "display yellow border around captured window",
                                                            OFFSET(display_border), AV_OPT_TYPE_BOOL,       { .i64 = 0 },      0, 1,          FLAGS },
    { "max_framerate",   "set maximum capture frame rate",  OFFSET(frame_rate),     AV_OPT_TYPE_VIDEO_RATE, { .str = "1000" }, 0.001, 1000,   FLAGS },
    { "hwnd",            "pre-existing HWND handle",        OFFSET(user_hwnd),      AV_OPT_TYPE_UINT64,     { .i64 = 0 },      0, UINT64_MAX, FLAGS },
    { "hmonitor",        "pre-existing HMONITOR handle",    OFFSET(user_hmonitor),  AV_OPT_TYPE_UINT64,     { .i64 = 0 },      0, UINT64_MAX, FLAGS },
    { "resize_mode",     "capture source resize behavior",  OFFSET(resize_mode),    AV_OPT_TYPE_INT, { .i64 = GFX_RESIZE_CROP }, 0, GFX_RESIZE_NB - 1, FLAGS, .unit = "resize_mode" },
    { "crop",            "crop or add black bars into frame", 0, AV_OPT_TYPE_CONST, { .i64 = GFX_RESIZE_CROP  }, 0, 0, FLAGS, .unit = "resize_mode" },
    { "scale",           "scale source to fit initial size",  0, AV_OPT_TYPE_CONST, { .i64 = GFX_RESIZE_SCALE }, 0, 0, FLAGS, .unit = "resize_mode" },
    { "scale_aspect",    "scale source to fit initial size while preserving aspect ratio",
                                                              0, AV_OPT_TYPE_CONST, { .i64 = GFX_RESIZE_SCALE_ASPECT }, 0, 0, FLAGS, .unit = "resize_mode" },
    { "scale_mode", "scaling algorithm",    OFFSET(scale_mode), AV_OPT_TYPE_INT, { .i64 = GFX_SCALE_BILINEAR }, 0, GFX_SCALE_NB - 1, FLAGS, .unit = "scale_mode" },
    { "point",      "use point scaling",    0, AV_OPT_TYPE_CONST, { .i64 = GFX_SCALE_POINT }, 0, 0, FLAGS, .unit = "scale_mode" },
    { "bilinear",   "use bilinear scaling", 0, AV_OPT_TYPE_CONST, { .i64 = GFX_SCALE_BILINEAR }, 0, 0, FLAGS, .unit = "scale_mode" },
    { "bicubic",    "use bicubic scaling",  0, AV_OPT_TYPE_CONST, { .i64 = GFX_SCALE_BICUBIC }, 0, 0, FLAGS, .unit = "scale_mode" },
    { NULL }
};

AVFILTER_DEFINE_CLASS(gfxcapture);

static const AVFilterPad gfxcapture_outputs[] = {
    {
        .name          = "default",
        .type          = AVMEDIA_TYPE_VIDEO,
        .request_frame = ff_gfxcapture_request_frame,
        .config_props  = ff_gfxcapture_config_props,
    },
};

const FFFilter ff_vsrc_gfxcapture = {
    .p.name        = "gfxcapture",
    .p.description = NULL_IF_CONFIG_SMALL("Capture graphics/screen content as a video source"),
    .p.priv_class  = &gfxcapture_class,
    .p.inputs      = NULL,
    .p.flags       = AVFILTER_FLAG_HWDEVICE,
    .priv_size     = sizeof(GfxCaptureContext),
    .init          = ff_gfxcapture_init,
    .uninit        = ff_gfxcapture_uninit,
    FILTER_OUTPUTS(gfxcapture_outputs),
    FILTER_SINGLE_PIXFMT(AV_PIX_FMT_D3D11),
    .flags_internal = FF_FILTER_FLAG_HWFRAME_AWARE,
};
