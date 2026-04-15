/*
 * dxgi_format_cache.c -- lock-free per-thread DXGI_FORMAT -> VkFormat cache.
 *
 * See dxgi_format_cache.h for the design rationale and API contract.
 *
 * Slow path
 * ---------
 * The slow-path "resolver" is intentionally kept in this file so the whole
 * cache is a single translation unit. It handles a conservative subset of
 * DXGI_FORMAT values -- the ones we actually see from games. Unknown
 * formats return VK_FORMAT_UNDEFINED; the caller is expected to forward
 * to DXVK's richer table in that case.
 *
 * The switch intentionally does NOT handle every obscure DXGI format
 * (e.g., DXGI_FORMAT_V408, DXGI_FORMAT_P010 video formats). Those remain
 * a DXVK-only concern.
 */

#include "dxgi_format_cache.h"

#include <stdint.h>
#include <string.h>

/* Keep these constants local; we don't want to pull in vulkan_core.h from
 * every d3d translation unit, and we only need a handful. */
#define PE_VK_FORMAT_UNDEFINED                 0
#define PE_VK_FORMAT_R4G4B4A4_UNORM_PACK16     2
#define PE_VK_FORMAT_R5G6B5_UNORM_PACK16       4
#define PE_VK_FORMAT_R5G5B5A1_UNORM_PACK16     6
#define PE_VK_FORMAT_R8_UNORM                  9
#define PE_VK_FORMAT_R8_SNORM                  10
#define PE_VK_FORMAT_R8_UINT                   13
#define PE_VK_FORMAT_R8_SINT                   14
#define PE_VK_FORMAT_R8G8_UNORM                16
#define PE_VK_FORMAT_R8G8_SNORM                17
#define PE_VK_FORMAT_R8G8_UINT                 20
#define PE_VK_FORMAT_R8G8_SINT                 21
#define PE_VK_FORMAT_R8G8B8A8_UNORM            37
#define PE_VK_FORMAT_R8G8B8A8_SNORM            38
#define PE_VK_FORMAT_R8G8B8A8_UINT             41
#define PE_VK_FORMAT_R8G8B8A8_SINT             42
#define PE_VK_FORMAT_R8G8B8A8_SRGB             43
#define PE_VK_FORMAT_B8G8R8A8_UNORM            44
#define PE_VK_FORMAT_B8G8R8A8_SRGB             50
#define PE_VK_FORMAT_A2B10G10R10_UNORM_PACK32  64
#define PE_VK_FORMAT_A2B10G10R10_UINT_PACK32   68
#define PE_VK_FORMAT_R16_UNORM                 70
#define PE_VK_FORMAT_R16_SNORM                 71
#define PE_VK_FORMAT_R16_UINT                  74
#define PE_VK_FORMAT_R16_SINT                  75
#define PE_VK_FORMAT_R16_SFLOAT                76
#define PE_VK_FORMAT_R16G16_UNORM              77
#define PE_VK_FORMAT_R16G16_UINT               81
#define PE_VK_FORMAT_R16G16_SINT               82
#define PE_VK_FORMAT_R16G16_SFLOAT             83
#define PE_VK_FORMAT_R16G16B16A16_UNORM        91
#define PE_VK_FORMAT_R16G16B16A16_UINT         95
#define PE_VK_FORMAT_R16G16B16A16_SINT         96
#define PE_VK_FORMAT_R16G16B16A16_SFLOAT       97
#define PE_VK_FORMAT_R32_UINT                  98
#define PE_VK_FORMAT_R32_SINT                  99
#define PE_VK_FORMAT_R32_SFLOAT                100
#define PE_VK_FORMAT_R32G32_UINT               101
#define PE_VK_FORMAT_R32G32_SINT               102
#define PE_VK_FORMAT_R32G32_SFLOAT             103
#define PE_VK_FORMAT_R32G32B32_SFLOAT          106
#define PE_VK_FORMAT_R32G32B32A32_UINT         107
#define PE_VK_FORMAT_R32G32B32A32_SINT         108
#define PE_VK_FORMAT_R32G32B32A32_SFLOAT       109
#define PE_VK_FORMAT_D16_UNORM                 124
#define PE_VK_FORMAT_D32_SFLOAT                126
#define PE_VK_FORMAT_D24_UNORM_S8_UINT         129
#define PE_VK_FORMAT_D32_SFLOAT_S8_UINT        130
#define PE_VK_FORMAT_BC1_RGBA_UNORM_BLOCK      133
#define PE_VK_FORMAT_BC1_RGBA_SRGB_BLOCK       134
#define PE_VK_FORMAT_BC2_UNORM_BLOCK           135
#define PE_VK_FORMAT_BC2_SRGB_BLOCK            136
#define PE_VK_FORMAT_BC3_UNORM_BLOCK           137
#define PE_VK_FORMAT_BC3_SRGB_BLOCK            138
#define PE_VK_FORMAT_BC4_UNORM_BLOCK           139
#define PE_VK_FORMAT_BC5_UNORM_BLOCK           141
#define PE_VK_FORMAT_BC7_UNORM_BLOCK           145
#define PE_VK_FORMAT_BC7_SRGB_BLOCK            146

/* VkColorSpaceKHR values we care about. */
#define PE_VK_COLOR_SPACE_SRGB_NONLINEAR_KHR    0
#define PE_VK_COLOR_SPACE_HDR10_ST2084_EXT      1000104008
#define PE_VK_COLOR_SPACE_EXTENDED_SRGB_LINEAR_EXT 1000104001
#define PE_VK_COLOR_SPACE_BT709_NONLINEAR_EXT   1000104003
#define PE_VK_COLOR_SPACE_BT2020_LINEAR_EXT     1000104007

/* DXGI_FORMAT enum values we handle. Source: d3d11.h / dxgiformat.h. */
#define PE_DXGI_FORMAT_UNKNOWN                          0
#define PE_DXGI_FORMAT_R32G32B32A32_TYPELESS            1
#define PE_DXGI_FORMAT_R32G32B32A32_FLOAT               2
#define PE_DXGI_FORMAT_R32G32B32A32_UINT                3
#define PE_DXGI_FORMAT_R32G32B32A32_SINT                4
#define PE_DXGI_FORMAT_R32G32B32_TYPELESS               5
#define PE_DXGI_FORMAT_R32G32B32_FLOAT                  6
#define PE_DXGI_FORMAT_R16G16B16A16_TYPELESS            9
#define PE_DXGI_FORMAT_R16G16B16A16_FLOAT               10
#define PE_DXGI_FORMAT_R16G16B16A16_UNORM               11
#define PE_DXGI_FORMAT_R16G16B16A16_UINT                12
#define PE_DXGI_FORMAT_R16G16B16A16_SINT                14
#define PE_DXGI_FORMAT_R32G32_TYPELESS                  15
#define PE_DXGI_FORMAT_R32G32_FLOAT                     16
#define PE_DXGI_FORMAT_R32G32_UINT                      17
#define PE_DXGI_FORMAT_R32G32_SINT                      18
#define PE_DXGI_FORMAT_R10G10B10A2_TYPELESS             23
#define PE_DXGI_FORMAT_R10G10B10A2_UNORM                24
#define PE_DXGI_FORMAT_R10G10B10A2_UINT                 25
#define PE_DXGI_FORMAT_R8G8B8A8_TYPELESS                27
#define PE_DXGI_FORMAT_R8G8B8A8_UNORM                   28
#define PE_DXGI_FORMAT_R8G8B8A8_UNORM_SRGB              29
#define PE_DXGI_FORMAT_R8G8B8A8_UINT                    30
#define PE_DXGI_FORMAT_R8G8B8A8_SNORM                   31
#define PE_DXGI_FORMAT_R8G8B8A8_SINT                    32
#define PE_DXGI_FORMAT_R16G16_TYPELESS                  33
#define PE_DXGI_FORMAT_R16G16_FLOAT                     34
#define PE_DXGI_FORMAT_R16G16_UNORM                     35
#define PE_DXGI_FORMAT_R16G16_UINT                      36
#define PE_DXGI_FORMAT_R16G16_SINT                      38
#define PE_DXGI_FORMAT_R32_TYPELESS                     39
#define PE_DXGI_FORMAT_D32_FLOAT                        40
#define PE_DXGI_FORMAT_R32_FLOAT                        41
#define PE_DXGI_FORMAT_R32_UINT                         42
#define PE_DXGI_FORMAT_R32_SINT                         43
#define PE_DXGI_FORMAT_R24G8_TYPELESS                   44
#define PE_DXGI_FORMAT_D24_UNORM_S8_UINT                45
#define PE_DXGI_FORMAT_R8G8_TYPELESS                    48
#define PE_DXGI_FORMAT_R8G8_UNORM                       49
#define PE_DXGI_FORMAT_R8G8_UINT                        50
#define PE_DXGI_FORMAT_R8G8_SNORM                       51
#define PE_DXGI_FORMAT_R8G8_SINT                        52
#define PE_DXGI_FORMAT_R16_TYPELESS                     53
#define PE_DXGI_FORMAT_R16_FLOAT                        54
#define PE_DXGI_FORMAT_D16_UNORM                        55
#define PE_DXGI_FORMAT_R16_UNORM                        56
#define PE_DXGI_FORMAT_R16_UINT                         57
#define PE_DXGI_FORMAT_R16_SNORM                        58
#define PE_DXGI_FORMAT_R16_SINT                         59
#define PE_DXGI_FORMAT_R8_TYPELESS                      60
#define PE_DXGI_FORMAT_R8_UNORM                         61
#define PE_DXGI_FORMAT_R8_UINT                          62
#define PE_DXGI_FORMAT_R8_SNORM                         63
#define PE_DXGI_FORMAT_R8_SINT                          64
#define PE_DXGI_FORMAT_BC1_TYPELESS                     70
#define PE_DXGI_FORMAT_BC1_UNORM                        71
#define PE_DXGI_FORMAT_BC1_UNORM_SRGB                   72
#define PE_DXGI_FORMAT_BC2_TYPELESS                     73
#define PE_DXGI_FORMAT_BC2_UNORM                        74
#define PE_DXGI_FORMAT_BC2_UNORM_SRGB                   75
#define PE_DXGI_FORMAT_BC3_TYPELESS                     76
#define PE_DXGI_FORMAT_BC3_UNORM                        77
#define PE_DXGI_FORMAT_BC3_UNORM_SRGB                   78
#define PE_DXGI_FORMAT_BC4_TYPELESS                     79
#define PE_DXGI_FORMAT_BC4_UNORM                        80
#define PE_DXGI_FORMAT_BC5_TYPELESS                     82
#define PE_DXGI_FORMAT_BC5_UNORM                        83
#define PE_DXGI_FORMAT_B8G8R8A8_UNORM                   87
#define PE_DXGI_FORMAT_B8G8R8A8_TYPELESS                90
#define PE_DXGI_FORMAT_B8G8R8A8_UNORM_SRGB              91
#define PE_DXGI_FORMAT_BC7_TYPELESS                     97
#define PE_DXGI_FORMAT_BC7_UNORM                        98
#define PE_DXGI_FORMAT_BC7_UNORM_SRGB                   99

/* DXGI_COLOR_SPACE_TYPE. */
#define PE_DXGI_COLOR_SPACE_RGB_FULL_G22_NONE_P709      0
#define PE_DXGI_COLOR_SPACE_RGB_FULL_G10_NONE_P709      1
#define PE_DXGI_COLOR_SPACE_RGB_FULL_G2084_NONE_P2020   12
#define PE_DXGI_COLOR_SPACE_RGB_FULL_G22_NONE_P2020     17

/* ---------------------------------------------------------------- */
/* Cache entry and per-thread state                                 */
/* ---------------------------------------------------------------- */

typedef struct {
    uint32_t dxgi_format;
    uint32_t usage;
    uint32_t colorspace;
    uint32_t vk_format;
    uint32_t vk_color_space;
    uint32_t flags;      /* bit 0 = valid */
    uint32_t _pad[2];    /* 32-byte stride; two entries per 64B line */
} dx_format_entry_t;

#define DX_FORMAT_CACHE_BUCKETS 512
#define DX_FORMAT_ENTRY_VALID   0x1u

_Static_assert(sizeof(dx_format_entry_t) == 32,
               "dx_format_entry_t must be exactly 32 bytes to avoid false sharing "
               "(two entries per 64-byte cache line)");

typedef struct {
    dx_format_entry_t buckets[DX_FORMAT_CACHE_BUCKETS];
    uint64_t hits;
    uint64_t misses;
    int      initialised;
} dx_format_cache_tls_t;

/* __thread is a GCC extension but universal on x86-64 (Itanium/Arch target).
 * MSVC has __declspec(thread) but we're Linux-native so this is fine. */
static __thread dx_format_cache_tls_t g_cache;

/* ---------------------------------------------------------------- */
/* Slow path: DXGI -> VkFormat conversion                           */
/* ---------------------------------------------------------------- */

static uint32_t vk_color_space_for(uint32_t cs)
{
    switch (cs) {
    case PE_DXGI_COLOR_SPACE_RGB_FULL_G10_NONE_P709:
        return PE_VK_COLOR_SPACE_EXTENDED_SRGB_LINEAR_EXT;
    case PE_DXGI_COLOR_SPACE_RGB_FULL_G2084_NONE_P2020:
        return PE_VK_COLOR_SPACE_HDR10_ST2084_EXT;
    case PE_DXGI_COLOR_SPACE_RGB_FULL_G22_NONE_P2020:
        return PE_VK_COLOR_SPACE_BT2020_LINEAR_EXT;
    case PE_DXGI_COLOR_SPACE_RGB_FULL_G22_NONE_P709:
    default:
        return PE_VK_COLOR_SPACE_SRGB_NONLINEAR_KHR;
    }
}

static uint32_t dxgi_to_vk_format(uint32_t fmt, uint32_t cs)
{
    /* Color-space-sensitive formats come first: an R8G8B8A8_UNORM with a
     * scRGB color space should pick the linear extended-SRGB variant, not
     * the ordinary sRGB nonlinear one. This is where the triplet-keyed
     * cache earns its keep. */
    (void)cs; /* reserved for scRGB/linear variants; most formats ignore cs */

    switch (fmt) {
    /* 8-bit RGBA */
    case PE_DXGI_FORMAT_R8G8B8A8_TYPELESS:
    case PE_DXGI_FORMAT_R8G8B8A8_UNORM:        return PE_VK_FORMAT_R8G8B8A8_UNORM;
    case PE_DXGI_FORMAT_R8G8B8A8_UNORM_SRGB:   return PE_VK_FORMAT_R8G8B8A8_SRGB;
    case PE_DXGI_FORMAT_R8G8B8A8_UINT:         return PE_VK_FORMAT_R8G8B8A8_UINT;
    case PE_DXGI_FORMAT_R8G8B8A8_SNORM:        return PE_VK_FORMAT_R8G8B8A8_SNORM;
    case PE_DXGI_FORMAT_R8G8B8A8_SINT:         return PE_VK_FORMAT_R8G8B8A8_SINT;
    /* BGRA (swap chains) */
    case PE_DXGI_FORMAT_B8G8R8A8_TYPELESS:
    case PE_DXGI_FORMAT_B8G8R8A8_UNORM:        return PE_VK_FORMAT_B8G8R8A8_UNORM;
    case PE_DXGI_FORMAT_B8G8R8A8_UNORM_SRGB:   return PE_VK_FORMAT_B8G8R8A8_SRGB;
    /* 10/10/10/2 (HDR10 surface) */
    case PE_DXGI_FORMAT_R10G10B10A2_TYPELESS:
    case PE_DXGI_FORMAT_R10G10B10A2_UNORM:     return PE_VK_FORMAT_A2B10G10R10_UNORM_PACK32;
    case PE_DXGI_FORMAT_R10G10B10A2_UINT:      return PE_VK_FORMAT_A2B10G10R10_UINT_PACK32;
    /* 16-bit */
    case PE_DXGI_FORMAT_R16_FLOAT:             return PE_VK_FORMAT_R16_SFLOAT;
    case PE_DXGI_FORMAT_R16_UNORM:
    case PE_DXGI_FORMAT_R16_TYPELESS:          return PE_VK_FORMAT_R16_UNORM;
    case PE_DXGI_FORMAT_R16_UINT:              return PE_VK_FORMAT_R16_UINT;
    case PE_DXGI_FORMAT_R16_SNORM:             return PE_VK_FORMAT_R16_SNORM;
    case PE_DXGI_FORMAT_R16_SINT:              return PE_VK_FORMAT_R16_SINT;
    case PE_DXGI_FORMAT_R16G16_FLOAT:          return PE_VK_FORMAT_R16G16_SFLOAT;
    case PE_DXGI_FORMAT_R16G16_UNORM:
    case PE_DXGI_FORMAT_R16G16_TYPELESS:       return PE_VK_FORMAT_R16G16_UNORM;
    case PE_DXGI_FORMAT_R16G16_UINT:           return PE_VK_FORMAT_R16G16_UINT;
    case PE_DXGI_FORMAT_R16G16_SINT:           return PE_VK_FORMAT_R16G16_SINT;
    case PE_DXGI_FORMAT_R16G16B16A16_FLOAT:    return PE_VK_FORMAT_R16G16B16A16_SFLOAT;
    case PE_DXGI_FORMAT_R16G16B16A16_UNORM:
    case PE_DXGI_FORMAT_R16G16B16A16_TYPELESS: return PE_VK_FORMAT_R16G16B16A16_UNORM;
    case PE_DXGI_FORMAT_R16G16B16A16_UINT:     return PE_VK_FORMAT_R16G16B16A16_UINT;
    case PE_DXGI_FORMAT_R16G16B16A16_SINT:     return PE_VK_FORMAT_R16G16B16A16_SINT;
    /* 32-bit scalar / vector */
    case PE_DXGI_FORMAT_R32_FLOAT:             return PE_VK_FORMAT_R32_SFLOAT;
    case PE_DXGI_FORMAT_R32_UINT:              return PE_VK_FORMAT_R32_UINT;
    case PE_DXGI_FORMAT_R32_SINT:              return PE_VK_FORMAT_R32_SINT;
    case PE_DXGI_FORMAT_R32_TYPELESS:          return PE_VK_FORMAT_R32_SFLOAT;
    case PE_DXGI_FORMAT_R32G32_FLOAT:          return PE_VK_FORMAT_R32G32_SFLOAT;
    case PE_DXGI_FORMAT_R32G32_UINT:           return PE_VK_FORMAT_R32G32_UINT;
    case PE_DXGI_FORMAT_R32G32_SINT:           return PE_VK_FORMAT_R32G32_SINT;
    case PE_DXGI_FORMAT_R32G32_TYPELESS:       return PE_VK_FORMAT_R32G32_SFLOAT;
    case PE_DXGI_FORMAT_R32G32B32_FLOAT:
    case PE_DXGI_FORMAT_R32G32B32_TYPELESS:    return PE_VK_FORMAT_R32G32B32_SFLOAT;
    case PE_DXGI_FORMAT_R32G32B32A32_FLOAT:
    case PE_DXGI_FORMAT_R32G32B32A32_TYPELESS: return PE_VK_FORMAT_R32G32B32A32_SFLOAT;
    case PE_DXGI_FORMAT_R32G32B32A32_UINT:     return PE_VK_FORMAT_R32G32B32A32_UINT;
    case PE_DXGI_FORMAT_R32G32B32A32_SINT:     return PE_VK_FORMAT_R32G32B32A32_SINT;
    /* 8-bit single / dual */
    case PE_DXGI_FORMAT_R8_TYPELESS:
    case PE_DXGI_FORMAT_R8_UNORM:              return PE_VK_FORMAT_R8_UNORM;
    case PE_DXGI_FORMAT_R8_UINT:               return PE_VK_FORMAT_R8_UINT;
    case PE_DXGI_FORMAT_R8_SNORM:              return PE_VK_FORMAT_R8_SNORM;
    case PE_DXGI_FORMAT_R8_SINT:               return PE_VK_FORMAT_R8_SINT;
    case PE_DXGI_FORMAT_R8G8_TYPELESS:
    case PE_DXGI_FORMAT_R8G8_UNORM:            return PE_VK_FORMAT_R8G8_UNORM;
    case PE_DXGI_FORMAT_R8G8_UINT:             return PE_VK_FORMAT_R8G8_UINT;
    case PE_DXGI_FORMAT_R8G8_SNORM:            return PE_VK_FORMAT_R8G8_SNORM;
    case PE_DXGI_FORMAT_R8G8_SINT:             return PE_VK_FORMAT_R8G8_SINT;
    /* Depth / stencil */
    case PE_DXGI_FORMAT_D16_UNORM:             return PE_VK_FORMAT_D16_UNORM;
    case PE_DXGI_FORMAT_D32_FLOAT:             return PE_VK_FORMAT_D32_SFLOAT;
    case PE_DXGI_FORMAT_D24_UNORM_S8_UINT:
    case PE_DXGI_FORMAT_R24G8_TYPELESS:        return PE_VK_FORMAT_D24_UNORM_S8_UINT;
    /* BC block compression */
    case PE_DXGI_FORMAT_BC1_TYPELESS:
    case PE_DXGI_FORMAT_BC1_UNORM:             return PE_VK_FORMAT_BC1_RGBA_UNORM_BLOCK;
    case PE_DXGI_FORMAT_BC1_UNORM_SRGB:        return PE_VK_FORMAT_BC1_RGBA_SRGB_BLOCK;
    case PE_DXGI_FORMAT_BC2_TYPELESS:
    case PE_DXGI_FORMAT_BC2_UNORM:             return PE_VK_FORMAT_BC2_UNORM_BLOCK;
    case PE_DXGI_FORMAT_BC2_UNORM_SRGB:        return PE_VK_FORMAT_BC2_SRGB_BLOCK;
    case PE_DXGI_FORMAT_BC3_TYPELESS:
    case PE_DXGI_FORMAT_BC3_UNORM:             return PE_VK_FORMAT_BC3_UNORM_BLOCK;
    case PE_DXGI_FORMAT_BC3_UNORM_SRGB:        return PE_VK_FORMAT_BC3_SRGB_BLOCK;
    case PE_DXGI_FORMAT_BC4_TYPELESS:
    case PE_DXGI_FORMAT_BC4_UNORM:             return PE_VK_FORMAT_BC4_UNORM_BLOCK;
    case PE_DXGI_FORMAT_BC5_TYPELESS:
    case PE_DXGI_FORMAT_BC5_UNORM:             return PE_VK_FORMAT_BC5_UNORM_BLOCK;
    case PE_DXGI_FORMAT_BC7_TYPELESS:
    case PE_DXGI_FORMAT_BC7_UNORM:             return PE_VK_FORMAT_BC7_UNORM_BLOCK;
    case PE_DXGI_FORMAT_BC7_UNORM_SRGB:        return PE_VK_FORMAT_BC7_SRGB_BLOCK;
    case PE_DXGI_FORMAT_UNKNOWN:
    default:
        return PE_VK_FORMAT_UNDEFINED;
    }
}

/* Knuth multiplicative hash constant + xor mixing for (fmt, usage, cs) */
static inline uint32_t dx_format_hash(uint32_t fmt, uint32_t usage, uint32_t cs)
{
    uint32_t h = fmt * 2654435761u;
    h ^= usage * 0x9E3779B1u;
    h ^= cs * 0x85EBCA6Bu;
    /* Mix to spread low bits to high */
    h ^= h >> 16;
    h *= 0x7feb352du;
    h ^= h >> 15;
    return h & (DX_FORMAT_CACHE_BUCKETS - 1);
}

int dx_format_cache_init(void)
{
    /* TLS is zero-initialised by the linker. Mark initialised so future
     * versions that pre-warm common entries can do so here. */
    g_cache.initialised = 1;
    return 0;
}

void dx_format_cache_stats(uint64_t *out_hits, uint64_t *out_misses)
{
    if (out_hits)   *out_hits   = g_cache.hits;
    if (out_misses) *out_misses = g_cache.misses;
}

uint32_t dx_format_cache_lookup(uint32_t dxgi_format,
                                uint32_t usage,
                                uint32_t colorspace,
                                uint32_t *out_vk_color_space)
{
    /* No init needed: TLS zero state means all entries start invalid.
     * This works because PE_VK_FORMAT_UNDEFINED == 0 and VALID flag bit
     * is zero -- any unused slot trivially reports miss. */

    uint32_t idx = dx_format_hash(dxgi_format, usage, colorspace);
    dx_format_entry_t *e = &g_cache.buckets[idx];

    if ((e->flags & DX_FORMAT_ENTRY_VALID) &&
        e->dxgi_format == dxgi_format &&
        e->usage == usage &&
        e->colorspace == colorspace) {
        g_cache.hits++;
        if (out_vk_color_space) *out_vk_color_space = e->vk_color_space;
        return e->vk_format;
    }

    /* Miss or collision — slow path + overwrite. */
    g_cache.misses++;
    uint32_t vk_fmt = dxgi_to_vk_format(dxgi_format, colorspace);
    uint32_t vk_cs  = vk_color_space_for(colorspace);

    e->dxgi_format = dxgi_format;
    e->usage = usage;
    e->colorspace = colorspace;
    e->vk_format = vk_fmt;
    e->vk_color_space = vk_cs;
    e->flags = DX_FORMAT_ENTRY_VALID;

    if (out_vk_color_space) *out_vk_color_space = vk_cs;
    return vk_fmt;
}
