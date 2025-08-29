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

#ifndef AVFILTER_VSRC_GFXCAPTURE_H
#define AVFILTER_VSRC_GFXCAPTURE_H

typedef struct GfxCaptureContextCpp GfxCaptureContextCpp;

enum GfxResizeMode {
    GFX_RESIZE_CROP = 0,
    GFX_RESIZE_SCALE,
    GFX_RESIZE_SCALE_ASPECT,
    GFX_RESIZE_NB
};

enum GfxScaleMode {
    GFX_SCALE_POINT = 0,
    GFX_SCALE_BILINEAR,
    GFX_SCALE_BICUBIC,
    GFX_SCALE_NB
};

typedef struct GfxCaptureContext {
    const AVClass *avclass;

    GfxCaptureContextCpp *ctx;

    const char *window_name;
    int monitor_idx;
    uint64_t user_hwnd;
    uint64_t user_hmonitor;
    int capture_cursor;
    int display_border;
    AVRational frame_rate;
    int resize_mode;
    int scale_mode;
} GfxCaptureContext;

av_cold int ff_gfxcapture_init(AVFilterContext *avctx);
av_cold void ff_gfxcapture_uninit(AVFilterContext *avctx);

int ff_gfxcapture_config_props(AVFilterLink *outlink);
int ff_gfxcapture_request_frame(AVFilterLink *outlink);

#endif /* AVFILTER_VSRC_GFXCAPTURE_H */
