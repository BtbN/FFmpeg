/*
 * VP8 HW decode acceleration through VA API
 *
 * Copyright (C) 2015 Timo Rothenpieler <timo@rothenpieler.org>
 *
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

#include <limits.h>
#include <stddef.h>
#include "libavutil/pixdesc.h"
#include "vaapi_internal.h"
#include "vp8.h"
#include "vp8data.h"

static void fill_picture_parameters(AVCodecContext              *avctx,
                                    const VP8Context            *h,
                                    VAPictureParameterBufferVP8 *pp)
{
    int i, j;

    pp->frame_width = avctx->width;
    pp->frame_height = avctx->height;

    if (h->framep[VP56_FRAME_PREVIOUS] && h->framep[VP56_FRAME_PREVIOUS]->tf.f->buf[0]) {
        pp->last_ref_frame = ff_vaapi_get_surface_id(h->framep[VP56_FRAME_PREVIOUS]->tf.f);
    } else {
        pp->last_ref_frame = VA_INVALID_ID;
    }

    if (h->framep[VP56_FRAME_GOLDEN] && h->framep[VP56_FRAME_GOLDEN]->tf.f->buf[0]) {
        pp->golden_ref_frame = ff_vaapi_get_surface_id(h->framep[VP56_FRAME_GOLDEN]->tf.f);
    } else {
        pp->golden_ref_frame = VA_INVALID_ID;
    }

    if (h->framep[VP56_FRAME_GOLDEN2] && h->framep[VP56_FRAME_GOLDEN2]->tf.f->buf[0]) {
        pp->alt_ref_frame = ff_vaapi_get_surface_id(h->framep[VP56_FRAME_GOLDEN2]->tf.f);
    } else {
        pp->alt_ref_frame = VA_INVALID_ID;
    }

    pp->out_of_loop_frame = VA_INVALID_ID;

    pp->pic_fields.bits.key_frame = !h->keyframe;
    pp->pic_fields.bits.version = h->profile;
    pp->pic_fields.bits.segmentation_enabled = h->segmentation.enabled;
    pp->pic_fields.bits.update_mb_segmentation_map = h->segmentation.update_map;
    pp->pic_fields.bits.update_segment_feature_data = h->segmentation.absolute_vals;
    pp->pic_fields.bits.filter_type = h->filter.simple;
    pp->pic_fields.bits.sharpness_level = h->filter.sharpness;
    pp->pic_fields.bits.loop_filter_adj_enable = h->lf_delta.enabled;
    pp->pic_fields.bits.mode_ref_lf_delta_update = h->lf_delta.update;
    pp->pic_fields.bits.sign_bias_golden = h->sign_bias[VP56_FRAME_GOLDEN];
    pp->pic_fields.bits.sign_bias_alternate = h->sign_bias[VP56_FRAME_GOLDEN2];
    pp->pic_fields.bits.mb_no_coeff_skip = h->update_probabilities;
    pp->pic_fields.bits.loop_filter_disable = h->mbskip_enabled;

    for (i = 0; i < 3; i++)
        pp->mb_segment_tree_probs[i] = h->prob->segmentid[i];

    for (i = 0; i < 4; i++) {
        pp->loop_filter_level[i] = h->segmentation.filter_level[i]; ///TODO: is this the right value?
        pp->loop_filter_deltas_ref_frame[i] = h->lf_delta.ref[i];
        pp->loop_filter_deltas_mode[i] = h->lf_delta.mode[MODE_I4x4 + i];
    }

    pp->prob_skip_false = h->prob->mbskip;
    pp->prob_intra = h->prob->intra;
    pp->prob_last = h->prob->last;
    pp->prob_gf = h->prob->golden;

    for (i = 0; i < 4; i++)
        pp->y_mode_probs[i] = h->prob->pred16x16[i];

    for (i = 0; i < 3; i++)
        pp->uv_mode_probs[i] = h->prob->pred8x8c[i];

    for (i = 0; i < 2; i++)
        for (j = 0; j < 19; j++)
            pp->mv_probs[i][j] = h->prob->mvc[i][j];

    /*
     * Let the stupidity begin
     */

    pp->bool_coder_ctx.range = h->rac_high;
    pp->bool_coder_ctx.value = (uint8_t) ((h->rac_code_word) >> 16);
    pp->bool_coder_ctx.count = (8 - h->rac_bits) % 8;

    av_log(avctx, AV_LOG_INFO, "rac_high: %x, rac_code_word: %x, rac_bits: %d\n",
           h->rac_high, h->rac_code_word, (int)h->rac_bits);
    av_log(avctx, AV_LOG_INFO, "range: %x, value: %x, count: %x\n",
           pp->bool_coder_ctx.range, pp->bool_coder_ctx.value, pp->bool_coder_ctx.count);
}

static int vaapi_vp8_start_frame(AVCodecContext          *avctx,
                                 av_unused const uint8_t *buffer,
                                 av_unused uint32_t       size)
{
    const VP8Context *h = avctx->priv_data;
    FFVAContext * const vactx = ff_vaapi_get_context(avctx);
    VAPictureParameterBufferVP8 *pic_param;
    VAProbabilityDataBufferVP8 *prob_data;
    VAIQMatrixBufferVP8 *iq_matrix;
    int i, j, k, l;

    vactx->slice_param_size = sizeof(VASliceParameterBufferVP8);

    pic_param = ff_vaapi_alloc_pic_param(vactx, sizeof(VAPictureParameterBufferVP8));
    if (!pic_param)
        return -1;
    fill_picture_parameters(avctx, h, pic_param);

    prob_data = ff_vaapi_alloc_probability(vactx, sizeof(VAProbabilityDataBufferVP8));
    if (!prob_data)
        return -1;

    for (i = 0; i < 4; i++)
        for (j = 0; j < 16; j++)
            for (k = 0; k < 3; k++)
                for (l = 0; l < 11; l++) {
                    ///TODO: propably fix j index lookup
                    prob_data->dct_coeff_probs[i][vp8_coeff_band[j]][k][l] = h->prob->token[i][j][k][l];
                }

    iq_matrix = ff_vaapi_alloc_iq_matrix(vactx, sizeof(VAIQMatrixBufferVP8));
    if (!iq_matrix)
        return -1;

    for (i = 0; i < 4; i++) {
        ///TODO: Check order/range
        iq_matrix->quantization_index[i][0] = h->qmat[i].luma_qmul[0];
        iq_matrix->quantization_index[i][1] = h->qmat[i].luma_qmul[1];
        iq_matrix->quantization_index[i][2] = h->qmat[i].luma_dc_qmul[0];
        iq_matrix->quantization_index[i][3] = h->qmat[i].luma_dc_qmul[1];
        iq_matrix->quantization_index[i][4] = h->qmat[i].chroma_qmul[0];
        iq_matrix->quantization_index[i][5] = h->qmat[i].chroma_qmul[1];
    }

    return 0;
}

static int vaapi_vp8_end_frame(AVCodecContext *avctx)
{
    FFVAContext * const vactx = ff_vaapi_get_context(avctx);
    const VP8Context *h = avctx->priv_data;
    int ret;

    ret = ff_vaapi_commit_slices(vactx);
    if (ret < 0)
        goto finish;

    ret = ff_vaapi_render_picture(vactx, ff_vaapi_get_surface_id(h->curframe->tf.f));
    if (ret < 0)
        goto finish;

finish:
    ff_vaapi_common_end_frame(avctx);
    return ret;
}

static int vaapi_vp8_decode_slice(AVCodecContext *avctx,
                                  const uint8_t  *buffer,
                                  uint32_t        size)
{
    FFVAContext * const vactx = ff_vaapi_get_context(avctx);
    const VP8Context *h = avctx->priv_data;
    VASliceParameterBufferVP8 *slice_param;
    int i;

    slice_param = (VASliceParameterBufferVP8*)ff_vaapi_alloc_slice(vactx, buffer, size);
    if (!slice_param)
        return -1;

    slice_param->macroblock_offset = h->header_size;
    slice_param->num_of_partitions = h->num_coeff_partitions + 1;

    for (i = 0; i < h->num_coeff_partitions; i++) {
        slice_param->partition_size[i + 1] = (8 - h->coeff_partition[i].bits) % 8;
    }

    slice_param->partition_size[0] = (8 - h->c.bits) % 8;

    return 0;
}

AVHWAccel ff_vp8_vaapi_hwaccel = {
    .name                 = "vp8_vaapi",
    .type                 = AVMEDIA_TYPE_VIDEO,
    .id                   = AV_CODEC_ID_VP8,
    .pix_fmt              = AV_PIX_FMT_VAAPI,
    .start_frame          = vaapi_vp8_start_frame,
    .end_frame            = vaapi_vp8_end_frame,
    .decode_slice         = vaapi_vp8_decode_slice,
    .init                 = ff_vaapi_context_init,
    .uninit               = ff_vaapi_context_fini,
    .priv_data_size       = sizeof(FFVAContext),
};
